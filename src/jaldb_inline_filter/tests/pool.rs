/***
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

use core::time::Duration;

use jalop::db::Pool;
use jalop_sys::RecordType;
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
