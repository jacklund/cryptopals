use crate::digest::sha1::SHA1;
use crate::digest::Digest;
use crate::util::{calculate_zscore, hexify, mean, std_deviation, unhexify};
use iron::prelude::*;
use iron::*;
use params::*;
use reqwest;
use std::time::{Duration, Instant};

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<SHA1>(key, message)
}

pub fn hmac<H>(key: &[u8], message: &[u8]) -> Vec<u8>
where
    H: Digest,
{
    // Get key the size of our block, derived from our key
    let mut blocksize_key: Vec<u8> = key.to_vec();

    // If it's bigger than a block, repeatedly hash until it's smaller
    if blocksize_key.len() > H::BLOCKSIZE {
        loop {
            blocksize_key = H::new().update(&blocksize_key).digest();
            if blocksize_key.len() <= H::BLOCKSIZE {
                break;
            }
        }
    };

    // Pad it to the right with zeroes
    if blocksize_key.len() < H::BLOCKSIZE {
        blocksize_key.extend(
            std::iter::repeat(0u8)
                .take(H::BLOCKSIZE - blocksize_key.len())
                .collect::<Vec<u8>>(),
        );
    }

    // H(K ^ ipad) || m
    let mut inner = blocksize_key
        .iter()
        .map(|a| a ^ 0x36u8)
        .collect::<Vec<u8>>();
    inner.extend_from_slice(message);
    let hashed_inner = H::new().update(&inner).digest();

    // (K ^ opad) || H((K ^ ipad) || m)
    let mut outer = blocksize_key
        .iter()
        .map(|a| a ^ 0x5cu8)
        .collect::<Vec<u8>>();
    outer.extend(hashed_inner);

    // Hash the whole thing
    H::new().update(&outer).digest()
}

pub struct HMacServer {
    sleep_time_msec: u64,
    key: Vec<u8>,
    use_insecure: bool,
}

fn secure_compare(valid: &[u8], signature: &[u8]) -> bool {
    valid == signature
}

fn insecure_compare(valid: &[u8], signature: &[u8], sleep_time_msec: u64) -> bool {
    for index in 0..signature.len() {
        if valid[index] != signature[index] {
            return false;
        }
        if sleep_time_msec > 0 {
            std::thread::sleep(Duration::from_millis(sleep_time_msec));
        }
    }
    println!("singature = {:?}, server returning 200", signature);
    true
}

fn handle_request(
    req: &mut Request,
    key: &[u8],
    sleep_time_msec: u64,
    use_insecure: bool,
) -> IronResult<Response> {
    let params = req.get_ref::<Params>().unwrap();
    let file = match params.get("file").unwrap() {
        Value::String(file) => file,
        _ => panic!("Got unknown value"),
    };
    let signature = match params.get("signature").unwrap() {
        Value::String(signature) => unhexify(signature).unwrap(),
        _ => panic!("Got unknown value"),
    };

    let valid = hmac_sha1(key, file.as_bytes());

    let is_valid = if use_insecure {
        insecure_compare(&valid, &signature, sleep_time_msec)
    } else {
        secure_compare(&valid, &signature)
    };

    if is_valid {
        Ok(Response::with(status::Ok))
    } else {
        Ok(Response::with(status::InternalServerError))
    }
}

impl HMacServer {
    pub fn new(sleep_time_msec: u64, use_insecure: bool) -> Self {
        Self {
            sleep_time_msec,
            key: "Yellow Submarine".as_bytes().to_vec(),
            use_insecure,
        }
    }

    pub fn start(&self) -> iron::error::HttpResult<Listening> {
        let sleep_time_msec = self.sleep_time_msec;
        let key: Vec<u8> = self.key.clone();
        let use_insecure = self.use_insecure;
        Iron::new(move |req: &mut Request| handle_request(req, &key, sleep_time_msec, use_insecure))
            .http("localhost:3000")
            .map_err(|e| e.into())
    }
}

pub async fn hmac_client(file: &str, signature: &[u8]) -> reqwest::StatusCode {
    let response = reqwest::get(format!(
        "http://localhost:3000/test?file={}&signature={}",
        file,
        hexify(&signature)
    ))
    .await
    .unwrap();

    response.status()
}

pub struct TimingAttack<'a, F>
where
    F: Fn(&[u8], &[u8]) -> bool,
{
    test_fn: &'a F,
    threshold: f32,
    measurements: Vec<u128>,
}

impl<'a, F> TimingAttack<'a, F>
where
    F: Fn(&[u8], &[u8]) -> bool,
{
    pub fn new(test_fn: &'a F, threshold: f32) -> Self {
        Self {
            test_fn,
            threshold,
            measurements: vec![],
        }
    }

    fn measure(&mut self, plaintext: &[u8], signature: &[u8]) -> (u128, bool) {
        let start = Instant::now();
        let status = (self.test_fn)(plaintext, signature);
        let duration = start.elapsed().as_millis();

        (duration, status)
    }

    fn check_zscore(&mut self, plaintext: &[u8], signature: &[u8], duration: u128) -> bool {
        // Figure out the zscore of this iteration, if it's over the threshold, we test again
        // just to make sure it's not an anomaly
        let zscore = calculate_zscore(&self.measurements, duration);
        if zscore.is_some() {
            println!(
                "signature = {:?}, duration = {}, zscore = {}, threshold = {}, over threshold = {}",
                signature,
                duration,
                zscore.unwrap(),
                self.threshold,
                zscore.unwrap() >= self.threshold
            );
            if zscore.unwrap() >= self.threshold {
                // Measure twice (or, in this case, 5 times), cut once
                let mut count = 0usize;
                for _ in 0..5 {
                    let (duration, _) = self.measure(plaintext, &signature);
                    let zscore = calculate_zscore(&self.measurements, duration);
                    println!(
                        "signature = {:?}, duration = {}, zscore = {}, mean = {}, std_dev = {}",
                        signature,
                        duration,
                        zscore.unwrap(),
                        mean(&self.measurements).unwrap(),
                        std_deviation(&self.measurements).unwrap(),
                    );
                    if zscore.unwrap() >= self.threshold {
                        count += 1;
                    }
                }

                // If the majority of "remeasurements" are greater than the threshold, accept
                // it
                if count > 2 {
                    return true;
                }
            }
        }

        false
    }

    fn find_value(&mut self, plaintext: &[u8], signature: &mut [u8], index: usize) -> Option<u8> {
        // Initialize
        self.measurements = Vec::new();

        // Warm up our stats
        signature[index] = 0;
        for _ in 0..10 {
            let (duration, _) = self.measure(plaintext, &signature);
            self.measurements.push(duration);
        }

        // Try each byte value until we find one that works (or don't)
        for byte in 0..=255u8 {
            signature[index] = byte;

            let (duration, status) = self.measure(plaintext, &signature);

            // We got the correct signature, exit
            if status {
                return Some(byte);
            }

            if self.check_zscore(plaintext, signature, duration) {
                return Some(byte);
            } else {
                self.measurements.push(duration);
            }
        }

        None
    }

    pub fn run<H>(&mut self, plaintext: &[u8]) -> Option<Vec<u8>>
    where
        H: Digest,
    {
        // Starting signature
        let mut signature = std::iter::repeat(0u8)
            .take(H::OUTPUT_SIZE)
            .collect::<Vec<u8>>();

        // Iterate through the signature
        let mut index: usize = 0;
        let mut retries: usize = 0;
        while index < H::OUTPUT_SIZE {
            match self.find_value(plaintext, &mut signature, index) {
                Some(value) => {
                    // Found it (we think), move on
                    signature[index] = value;
                    index += 1;
                }

                // No luck, either try again (might be a false negative due to noise) or, if
                // retrying didn't work, back up to the previous index and try there (the theory
                // being that maybe the previous one was a false positive, causing this one to fail
                // all the time)
                None => {
                    if retries == 1 {
                        retries = 0;
                        index -= 1;
                    } else {
                        retries += 1;
                    }
                }
            }
        }

        Some(signature)
    }
}

// Convenience function
pub fn hmac_timing_attack<H, F>(test_fn: &F, plaintext: &[u8], threshold: f32) -> Option<Vec<u8>>
where
    H: Digest,
    F: Fn(&[u8], &[u8]) -> bool,
{
    let mut attack = TimingAttack::new(test_fn, threshold);
    attack.run::<H>(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhexify;
    use reqwest;

    #[test]
    fn test_hmac_sha1() {
        let string = "Terminator X: Bring the noise";
        let key = "SuperSecretKey";

        assert_eq!(
            unhexify("b40438338a19a7d879221946330058bbda92d7f8").unwrap(),
            hmac_sha1(key.as_bytes(), string.as_bytes())
        );
    }

    #[tokio::test]
    async fn test_hmac_server() {
        let key = "Yellow Submarine";
        let mut server = HMacServer::new(0, false).start().unwrap();

        let file = "foo";
        let signature = hmac_sha1(key.as_bytes(), file.as_bytes());

        assert_eq!(reqwest::StatusCode::OK, hmac_client(file, &signature).await);

        assert_eq!(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            hmac_client("foobar", &signature).await,
        );
        server.close().unwrap();
    }
}
