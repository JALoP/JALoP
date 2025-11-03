use core::time::Duration;

use jalop::db::Pool;
use jalop_sys::{flags::DbFlags, RecordType};
use tokio::{
    test,
    time::{interval, sleep},
};

#[test]
#[ignore = "needs proper setup"]
async fn simple() -> anyhow::Result<()> {
    let (p, _) = Pool::new("/tmp/testdb")?;

    for i in 1..5 {
        tokio::spawn({
            let r = p.reader().await?;
            async move {
                let mut timeout = interval(Duration::from_millis(100 * i as u64));
                while let Ok(_) = r.get_next_unsynced_record(RecordType::Journal) {
                    eprintln!("{i}: read");
                    timeout.tick().await;
                }
                println!("reader stopped");
            }
        });
    }
    sleep(Duration::from_secs(5)).await;
    p.shutdown(Duration::from_secs(1)).await?;

    Ok(())
}
