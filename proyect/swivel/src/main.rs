use aya::{Ebpf, EbpfError};
use commons::{event_wire::parse_event, events::Event};
#[rustfmt::skip]
use log::{debug, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = load_ebpf()?;
    start_logger(&mut ebpf);
    
    let events_map = ebpf.take_map("EVENTS")
        .expect("No se encontró el mapa EVENTS");

    spawn_reader(events_map)?;
    
    let btf = aya::Btf::from_sys_fs()?;
    let program: &mut aya::programs::Lsm = ebpf.program_mut("bprm_check_security").unwrap().try_into()?;
    
    program.load("bprm_check_security", &btf)?;
    
    program.attach()?;

    let ctrl_c = tokio::signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn load_ebpf() -> Result<Ebpf, EbpfError> {
    let aya = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/spark"
    )))?;

    Ok(aya)
}

fn start_logger(mut ebpf: &mut Ebpf){
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => { warn!("failed to initialize eBPF logger: {e}"); }
        Ok(logger) => {
            let logger_res = tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE);
            if let Ok(mut logger) = logger_res{
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
            }
        }
    }

}

fn spawn_reader(events_map: aya::maps::Map) -> anyhow::Result<()> {
    let ring_buf = aya::maps::RingBuf::try_from(events_map)?;
    let mut async_events = tokio::io::unix::AsyncFd::new(ring_buf)?;

    tokio::task::spawn(async move {
        loop {
            let mut guard = match async_events.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    println!("Error esperando eventos: {}", e);
                    break;
                }
            };

            let ring_buf = guard.get_inner_mut();
            
            while let Some(item) = ring_buf.next() {
                let raw_bytes = item.as_ref();
                println!("Evento recibido: {} bytes", raw_bytes.len());
                let event = parse_event(&raw_bytes);
                 match event {
                    Ok(e) => {
                        let clean_event = Event::from_raw(e);
                        match clean_event  {
                            Ok(event) => {
                                 println!("Evento parseado a {:#?}", event);
                            },
                            Err(err) => {
                                println!("Evento fallado {:?}", err);
                             } ,
                        }
                                           }
                    Err(err) => {
                        println!("Evento fallado {:?}", err);
                    }
                }

            }

            guard.clear_ready();
        }
    });

    Ok(())
}
