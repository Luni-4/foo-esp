use core::net::{Ipv4Addr, Ipv6Addr};

use edge_mdns::buf::{BufferAccess, VecBufAccess};
use edge_mdns::domain::base::Ttl;
use edge_mdns::host::{Service, ServiceAnswers};
use edge_mdns::io::{self, MdnsIoError, DEFAULT_SOCKET};
use edge_mdns::{host::Host, HostAnswersMdnsHandler};
use edge_nal::{UdpBind, UdpSplit};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;

use log::info;

use anyhow::{anyhow, bail};

use esp_idf_svc::wifi::{AuthMethod, ClientConfiguration, Configuration};

use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::hal::task::block_on;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::timer::EspTaskTimerService;
use esp_idf_svc::wifi::{AsyncWifi, EspWifi};
use esp_idf_svc::{eventloop::EspSystemEventLoop, nvs::EspDefaultNvsPartition};

const OUR_NAME: &str = "mypc";

const SERVICE_NAME: &str = "my-service";

#[toml_cfg::toml_config]
pub struct WifiConfig {
    #[default("")]
    ssid: &'static str,
    #[default("")]
    password: &'static str,
}

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    EspLogger::initialize_default();

    // `async-io` uses the ESP IDF `eventfd` syscall to implement async IO.
    // If you use `tokio`, you still have to do the same as it also uses the `eventfd` syscall
    let _event = esp_idf_svc::io::vfs::MountedEventfs::mount(5)?;

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let timer_service = EspTaskTimerService::new()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = AsyncWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
        timer_service,
    )?;

    block_on(connect_wifi(&mut wifi))?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;

    info!("Wifi DHCP info: {:?}", ip_info);

    let stack = edge_nal_std::Stack::new();

    let (recv_buf, send_buf) = (
        VecBufAccess::<NoopRawMutex, 1500>::new(),
        VecBufAccess::<NoopRawMutex, 1500>::new(),
    );

    block_on(run::<edge_nal_std::Stack, _, _>(
        &stack, &recv_buf, &send_buf, OUR_NAME, ip_info.ip,
    ))
    .map_err(|e| anyhow!("Error running mdns-sd: {e}"))?;

    loop {
        // Sleep for one second and then continue the execution.
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

async fn run<T, RB, SB>(
    stack: &T,
    recv_buf: RB,
    send_buf: SB,
    our_name: &str,
    our_ip: Ipv4Addr,
) -> Result<(), MdnsIoError<T::Error>>
where
    T: UdpBind,
    RB: BufferAccess<[u8]>,
    SB: BufferAccess<[u8]>,
{
    info!("About to run an mDNS responder for our PC. It will be addressable using {our_name}.local, so try to `ping {our_name}.local`.");

    // No ipv6 up and running.
    // To have it running, we need to get at least a link-local ipv6 addr
    // first, using an `esp-idf-sys` API call once the wifi is up and running:
    // `esp_idf_svc::sys::esp_netif_create_ip6_linklocal`.
    // Moreover, we can't just pass "0" for the interface.
    // We need to pass `wifi.sta_netif().index()`
    // Sometimes, "0" does work on PCs, but not with ESP-IDF.
    // This API is very picky about having a correct ipv6-capable
    // interface rather than just "all" (= 0).
    let mut socket = io::bind(stack, DEFAULT_SOCKET, Some(Ipv4Addr::UNSPECIFIED), None).await?;

    let (recv, send) = socket.split();

    let host = Host {
        hostname: our_name,
        ipv4: our_ip,
        ipv6: Ipv6Addr::UNSPECIFIED,
        ttl: Ttl::from_secs(60),
    };

    let service = Service {
        name: SERVICE_NAME,
        priority: 1,
        weight: 5,
        service: "_https",
        protocol: "_tcp",
        port: 443,
        service_subtypes: &[],
        txt_kvs: &[],
    };

    // A way to notify the mDNS responder that the data in `Host` had changed
    // Not necessary for this example, because the data is hard-coded
    let signal = Signal::new();

    let mdns = io::Mdns::<NoopRawMutex, _, _, _, _>::new(
        Some(Ipv4Addr::UNSPECIFIED),
        // No ipv6 up and running.
        None,
        recv,
        send,
        recv_buf,
        send_buf,
        |_buf| {},
        &signal,
    );

    mdns.run(HostAnswersMdnsHandler::new(ServiceAnswers::new(
        &host, &service,
    )))
    .await
}

async fn connect_wifi(wifi: &mut AsyncWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    let wifi_config = WIFI_CONFIG;

    let ssid = wifi_config.ssid;
    let password = wifi_config.password;

    if ssid.is_empty() {
        bail!("Missing Wi-Fi SSID")
    }

    if password.is_empty() {
        bail!("Wifi password is empty");
    }

    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: ssid.try_into().unwrap(),
        bssid: None,
        auth_method: AuthMethod::WPA2Personal,
        password: password.try_into().unwrap(),
        channel: None,
        ..Default::default()
    });

    wifi.set_configuration(&wifi_configuration)?;

    wifi.start().await?;
    info!("Wifi started");

    wifi.connect().await?;
    info!("Wifi connected");

    wifi.wait_netif_up().await?;
    info!("Wifi netif up");

    Ok(())
}
