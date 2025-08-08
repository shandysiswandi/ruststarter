//! A robust, thread-safe Snowflake ID generator.
//!
//! This module provides a `Snowflake` generator that creates unique 64-bit IDs,
//! suitable for use as primary keys in a distributed system. The generated IDs are
//! roughly time-sortable.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SnowflakeError {
    #[error("Worker ID {worker_id} is out of the valid range (0-{MAX_WORKER_ID})")]
    WorkerIdOutOfRange { worker_id: u16 },

    #[error("System clock moved backwards. Cannot generate new IDs.")]
    ClockMovedBackwards,

    #[error("Generated ID has exceeded the maximum value for a signed 64-bit integer.")]
    IdOverflow,
}

#[cfg_attr(test, mockall::automock)]
pub trait Generator: Send + Sync {
    fn generate(&self) -> Result<i64, SnowflakeError>;
}

// The default epoch is 2025-01-01 00:00:00 UTC
const DEFAULT_EPOCH: u64 = 1735689600000;
const WORKER_ID_BITS: u8 = 10;
const SEQUENCE_BITS: u8 = 12;

// The maximum values are derived from the bit counts
const MAX_WORKER_ID: u16 = (1 << WORKER_ID_BITS) - 1;
const MAX_SEQUENCE: u16 = (1 << SEQUENCE_BITS) - 1;

// Bit shifts for constructing the ID
const WORKER_ID_SHIFT: u8 = SEQUENCE_BITS;
const TIMESTAMP_SHIFT: u8 = SEQUENCE_BITS + WORKER_ID_BITS;

struct SnowflakeState {
    last_timestamp: u64,
    sequence: u16,
}

pub struct Snowflake {
    worker_id: u16,
    epoch: u64,
    state: Mutex<SnowflakeState>,
}

impl Snowflake {
    pub fn builder(worker_id: u16) -> SnowflakeBuilder {
        SnowflakeBuilder::new(worker_id)
    }

    fn wait_for_next_millis(&self, current_timestamp: u64) -> u64 {
        let mut new_timestamp = self.current_timestamp_millis();
        while new_timestamp <= current_timestamp {
            std::thread::yield_now();
            new_timestamp = self.current_timestamp_millis();
        }
        new_timestamp
    }

    fn current_timestamp_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("BUG: System time is before the UNIX epoch!")
            .as_millis() as u64
            - self.epoch
    }
}

impl Generator for Snowflake {
    fn generate(&self) -> Result<i64, SnowflakeError> {
        let mut state = self.state.lock().expect("BUG: Snowflake mutex was poisoned!");
        let mut timestamp = self.current_timestamp_millis();

        if timestamp < state.last_timestamp {
            return Err(SnowflakeError::ClockMovedBackwards);
        }

        if timestamp == state.last_timestamp {
            state.sequence = (state.sequence + 1) & MAX_SEQUENCE;
            if state.sequence == 0 {
                timestamp = self.wait_for_next_millis(state.last_timestamp);
            }
        } else {
            state.sequence = 0;
        }

        state.last_timestamp = timestamp;

        let id_u64: u64 = (timestamp << TIMESTAMP_SHIFT)
            | ((self.worker_id as u64) << WORKER_ID_SHIFT)
            | (state.sequence as u64);

        if id_u64 > i64::MAX as u64 {
            return Err(SnowflakeError::IdOverflow);
        }

        Ok(id_u64 as i64)
    }
}

pub struct SnowflakeBuilder {
    worker_id: u16,
    epoch: u64,
}

impl SnowflakeBuilder {
    pub fn new(worker_id: u16) -> Self {
        Self {
            worker_id,
            epoch: DEFAULT_EPOCH,
        }
    }

    pub fn with_epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }

    pub fn build(self) -> Result<Snowflake, SnowflakeError> {
        if self.worker_id > MAX_WORKER_ID {
            return Err(SnowflakeError::WorkerIdOutOfRange {
                worker_id: self.worker_id,
            });
        }

        let initial_state = SnowflakeState {
            last_timestamp: 0,
            sequence: 0,
        };

        Ok(Snowflake {
            worker_id: self.worker_id,
            epoch: self.epoch,
            state: Mutex::new(initial_state),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn builder_should_succeed_with_valid_worker_id() {
        let generator = Snowflake::builder(0).build();
        assert!(generator.is_ok());

        let generator = Snowflake::builder(MAX_WORKER_ID).build();
        assert!(generator.is_ok());
    }

    #[test]
    fn builder_should_fail_with_invalid_worker_id() {
        let result = Snowflake::builder(MAX_WORKER_ID + 1).build();
        assert!(matches!(result, Err(SnowflakeError::WorkerIdOutOfRange { .. })));
    }

    #[test]
    fn should_wait_for_next_millisecond_on_sequence_overflow() {
        let generator = Snowflake::builder(1).build().unwrap();
        let mut ids = HashSet::new();
        let num_ids = MAX_SEQUENCE as usize + 2;

        for _ in 0..num_ids {
            let id = generator.generate().unwrap();
            assert!(ids.insert(id), "Duplicate ID generated on sequence overflow");
        }
        assert_eq!(ids.len(), num_ids);
    }

    #[test]
    fn generated_ids_should_be_roughly_time_sortable() {
        let generator = Snowflake::builder(1).build().unwrap();
        let id1 = generator.generate().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let id2 = generator.generate().unwrap();
        assert!(id2 > id1, "ID2 should be greater than ID1");
    }

    #[test]
    fn should_generate_unique_ids_across_multiple_threads() {
        let generator = Arc::new(Snowflake::builder(10).build().unwrap());
        let num_threads = 8;
        let ids_per_thread = 5_000;
        let mut handles = vec![];

        for _ in 0..num_threads {
            let generator_clone = Arc::clone(&generator);
            let handle = thread::spawn(move || {
                let mut ids = Vec::with_capacity(ids_per_thread);
                for _ in 0..ids_per_thread {
                    ids.push(generator_clone.generate().unwrap());
                }
                ids
            });
            handles.push(handle);
        }

        let mut all_ids = HashSet::new();
        for handle in handles {
            let ids = handle.join().unwrap();
            for id in ids {
                assert!(all_ids.insert(id), "Found duplicate ID in multi-threaded test");
            }
        }

        assert_eq!(all_ids.len(), num_threads * ids_per_thread);
    }

    // this test is need a very long time to run
    // #[test]
    // fn should_fail_on_i64_overflow() {
    //     // This test will fail if the epoch is too far in the past.
    //     // We set an epoch that is far enough in the past to trigger an overflow.
    //     let far_past_epoch = 1_000_000_000_000; // A time far enough in the past to cause an overflow
    //     let generator = Snowflake::builder(1)
    //         .with_epoch(far_past_epoch)
    //         .build()
    //         .unwrap();

    //     // Repeatedly generate IDs until an overflow occurs
    //     let mut overflow_detected = false;
    //     loop {
    //         match generator.generate() {
    //             Ok(_) => {
    //                 // Continue generating
    //             },
    //             Err(SnowflakeError::IdOverflow) => {
    //                 overflow_detected = true;
    //                 break;
    //             },
    //             Err(e) => panic!("Unexpected error: {:?}", e),
    //         }
    //         if overflow_detected {
    //             break;
    //         }
    //     }

    //     assert!(
    //         overflow_detected,
    //         "An i64 overflow should have been detected."
    //     );
    // }
}
