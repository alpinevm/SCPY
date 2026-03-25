use std::collections::BTreeMap;

pub const CODE_LENGTHS: [u8; 4] = [3, 4, 5, 6];
pub const BASE56_ALPHABET: &[u8; 56] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
const PERMUTATION_ROUNDS: u8 = 8;
const PERMUTATION_KEY: u64 = 0xA5C3_1F27_9BDE_4401;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeAllocation {
    pub room_id: String,
    pub code_len: u8,
    pub local_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeOutcome {
    Freed,
    AlreadyFree,
}

#[derive(Clone, Debug)]
pub struct TieredAllocator {
    intervals: BTreeMap<u8, BTreeMap<u64, u64>>,
}

impl Default for TieredAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl TieredAllocator {
    pub fn new() -> Self {
        let mut allocator = Self::empty();
        for code_len in CODE_LENGTHS {
            let end = tier_capacity(code_len).expect("valid tier") - 1;
            allocator
                .seed_tier(code_len, &[(0, end)])
                .expect("default allocator tier must seed");
        }

        allocator
    }

    pub fn empty() -> Self {
        let mut intervals = BTreeMap::new();
        for code_len in CODE_LENGTHS {
            intervals.insert(code_len, BTreeMap::new());
        }

        Self { intervals }
    }

    pub fn seed_tier(&mut self, code_len: u8, intervals: &[(u64, u64)]) -> Option<()> {
        let capacity = tier_capacity(code_len)?;
        let tier = self.intervals.get_mut(&code_len)?;
        tier.clear();

        for (start, end) in intervals {
            if start > end || *end >= capacity {
                return None;
            }
            tier.insert(*start, *end);
        }

        Some(())
    }

    pub fn allocate(&mut self) -> Option<CodeAllocation> {
        for code_len in CODE_LENGTHS {
            if let Some(tier) = self.intervals.get_mut(&code_len) {
                if let Some((&start, &end)) = tier.iter().next() {
                    tier.remove(&start);
                    if start < end {
                        tier.insert(start + 1, end);
                    }

                    return Some(CodeAllocation {
                        room_id: encode_local_id(code_len, start)?,
                        code_len,
                        local_id: start,
                    });
                }
            }
        }

        None
    }

    pub fn free(&mut self, code_len: u8, local_id: u64) -> Option<FreeOutcome> {
        let capacity = tier_capacity(code_len)?;
        if local_id >= capacity {
            return None;
        }

        let tier = self.intervals.get_mut(&code_len)?;
        let left = tier
            .range(..=local_id)
            .next_back()
            .map(|(&start, &end)| (start, end));
        if let Some((start, end)) = left {
            if start <= local_id && local_id <= end {
                return Some(FreeOutcome::AlreadyFree);
            }
        }

        let left_adjacent =
            left.and_then(|(start, end)| (end + 1 == local_id).then_some((start, end)));
        let right_adjacent = local_id
            .checked_add(1)
            .and_then(|next| tier.get(&next).copied().map(|end| (next, end)));

        match (left_adjacent, right_adjacent) {
            (Some((left_start, _left_end)), Some((right_start, right_end))) => {
                tier.insert(left_start, right_end);
                tier.remove(&right_start);
            }
            (Some((left_start, _left_end)), None) => {
                tier.insert(left_start, local_id);
            }
            (None, Some((right_start, right_end))) => {
                tier.remove(&right_start);
                tier.insert(local_id, right_end);
            }
            (None, None) => {
                tier.insert(local_id, local_id);
            }
        }

        Some(FreeOutcome::Freed)
    }

    pub fn intervals(&self, code_len: u8) -> Option<Vec<(u64, u64)>> {
        self.intervals
            .get(&code_len)
            .map(|tier| tier.iter().map(|(&start, &end)| (start, end)).collect())
    }
}

pub fn tier_capacity(code_len: u8) -> Option<u64> {
    if !CODE_LENGTHS.contains(&code_len) {
        return None;
    }

    Some(56_u64.pow(u32::from(code_len)))
}

pub fn encode_local_id(code_len: u8, local_id: u64) -> Option<String> {
    let capacity = tier_capacity(code_len)?;
    if local_id >= capacity {
        return None;
    }

    let mut value = permute_local_id(code_len, local_id)?;
    let code_len_usize = usize::from(code_len);
    let mut chars = vec![BASE56_ALPHABET[0] as char; usize::from(code_len)];
    for slot in (0..code_len_usize).rev() {
        let digit = (value % BASE56_ALPHABET.len() as u64) as usize;
        chars[slot] = BASE56_ALPHABET[digit] as char;
        value /= BASE56_ALPHABET.len() as u64;
    }

    Some(chars.into_iter().collect())
}

pub fn decode_room_id(room_id: &str) -> Option<CodeAllocation> {
    let (code_len, encoded_rank) = decode_public_rank(room_id)?;
    let local_id = invert_permuted_local_id(code_len, encoded_rank)?;

    Some(CodeAllocation {
        room_id: room_id.to_string(),
        code_len,
        local_id,
    })
}

fn decode_public_rank(room_id: &str) -> Option<(u8, u64)> {
    let code_len = u8::try_from(room_id.len()).ok()?;
    tier_capacity(code_len)?;

    let mut encoded_rank = 0_u64;
    for byte in room_id.bytes() {
        let digit = BASE56_ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)? as u64;
        encoded_rank = encoded_rank * BASE56_ALPHABET.len() as u64 + digit;
    }

    Some((code_len, encoded_rank))
}

fn permute_local_id(code_len: u8, local_id: u64) -> Option<u64> {
    let domain = tier_capacity(code_len)?;
    let mut value = local_id;
    loop {
        value = feistel_encrypt(value, code_len)?;
        if value < domain {
            return Some(value);
        }
    }
}

fn invert_permuted_local_id(code_len: u8, encoded_rank: u64) -> Option<u64> {
    let domain = tier_capacity(code_len)?;
    if encoded_rank >= domain {
        return None;
    }

    let mut value = encoded_rank;
    loop {
        value = feistel_decrypt(value, code_len)?;
        if value < domain {
            return Some(value);
        }
    }
}

fn feistel_encrypt(value: u64, code_len: u8) -> Option<u64> {
    let half_bits = permutation_half_bits(code_len)?;
    let mask = (1_u64 << half_bits) - 1;
    let mut left = value >> half_bits;
    let mut right = value & mask;

    for round in 0..PERMUTATION_ROUNDS {
        let next_left = right;
        let next_right = left ^ round_function(code_len, round, right, mask);
        left = next_left;
        right = next_right;
    }

    Some((left << half_bits) | right)
}

fn feistel_decrypt(value: u64, code_len: u8) -> Option<u64> {
    let half_bits = permutation_half_bits(code_len)?;
    let mask = (1_u64 << half_bits) - 1;
    let mut left = value >> half_bits;
    let mut right = value & mask;

    for round in (0..PERMUTATION_ROUNDS).rev() {
        let previous_right = left;
        let previous_left = right ^ round_function(code_len, round, left, mask);
        left = previous_left;
        right = previous_right;
    }

    Some((left << half_bits) | right)
}

fn round_function(code_len: u8, round: u8, value: u64, mask: u64) -> u64 {
    let seed = PERMUTATION_KEY ^ (u64::from(code_len) << 56) ^ (u64::from(round) << 48) ^ value;
    splitmix64(seed) & mask
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn permutation_half_bits(code_len: u8) -> Option<u32> {
    match code_len {
        3 => Some(9),
        4 => Some(12),
        5 => Some(15),
        6 => Some(18),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        decode_room_id, encode_local_id, feistel_decrypt, feistel_encrypt, tier_capacity,
        FreeOutcome, TieredAllocator, BASE56_ALPHABET,
    };

    #[test]
    fn public_ids_roundtrip_back_to_internal_ids() {
        let samples = [
            (3, 0),
            (3, 1),
            (3, 55),
            (3, 56),
            (4, 0),
            (4, 4096),
            (5, 1024),
            (6, tier_capacity(6).expect("tier") - 1),
        ];

        for (code_len, local_id) in samples {
            let encoded = encode_local_id(code_len, local_id).expect("encoding must succeed");
            let decoded = decode_room_id(&encoded).expect("decoding must succeed");
            assert_eq!(decoded.code_len, code_len);
            assert_eq!(decoded.local_id, local_id);
        }
    }

    #[test]
    fn allocator_allocates_shortest_codes_first() {
        let mut allocator = TieredAllocator::new();

        let first = allocator.allocate().expect("allocation");
        let second = allocator.allocate().expect("allocation");
        let third = allocator.allocate().expect("allocation");

        assert_eq!(first.local_id, 0);
        assert_eq!(second.local_id, 1);
        assert_eq!(third.local_id, 2);
        assert_ne!(
            first.room_id,
            encode_local_id(3, 1).expect("code must encode")
        );
    }

    #[test]
    fn allocator_free_is_idempotent_and_merges_neighbors() {
        let mut allocator = TieredAllocator::new();
        let _first = allocator.allocate().expect("allocation");
        let second = allocator.allocate().expect("allocation");
        let _third = allocator.allocate().expect("allocation");

        assert_eq!(
            allocator.free(second.code_len, second.local_id),
            Some(FreeOutcome::Freed)
        );
        assert_eq!(
            allocator.free(second.code_len, second.local_id),
            Some(FreeOutcome::AlreadyFree)
        );
    }

    #[test]
    fn permutation_is_not_plain_base56_counting() {
        let first_codes = (0_u64..16)
            .map(|local_id| encode_local_id(3, local_id).expect("code must encode"))
            .collect::<Vec<_>>();

        let naive_codes = (0_u64..16)
            .map(|local_id| {
                let mut value = local_id;
                let mut chars = vec!['2'; 3];
                for slot in (0..3).rev() {
                    let digit = (value % 56) as usize;
                    chars[slot] = super::BASE56_ALPHABET[digit] as char;
                    value /= 56;
                }
                chars.into_iter().collect::<String>()
            })
            .collect::<Vec<_>>();

        assert_ne!(first_codes, naive_codes);
        assert_eq!(
            first_codes.iter().collect::<HashSet<_>>().len(),
            first_codes.len()
        );
    }

    #[test]
    fn feistel_roundtrip_holds_on_superset_domain() {
        for code_len in [3_u8, 4, 5, 6] {
            for value in 0_u64..256 {
                let encrypted = feistel_encrypt(value, code_len).expect("encrypt must work");
                let decrypted = feistel_decrypt(encrypted, code_len).expect("decrypt must work");
                assert_eq!(decrypted, value);
            }
        }
    }

    #[test]
    fn decode_room_id_rejects_invalid_lengths_and_alphabet() {
        for invalid in ["", "22", "2222222", "0OO", "lIl", "abc!"] {
            assert!(
                decode_room_id(invalid).is_none(),
                "{invalid} should be rejected"
            );
        }
    }

    macro_rules! exhaustive_roundtrip_tier_test {
        ($name:ident, $code_len:expr, $count:expr) => {
            #[test]
            fn $name() {
                for local_id in 0_u64..$count {
                    let encoded =
                        encode_local_id($code_len, local_id).expect("encoding must succeed");
                    let decoded = decode_room_id(&encoded).expect("decoding must succeed");
                    assert_eq!(decoded.code_len, $code_len);
                    assert_eq!(decoded.local_id, local_id);
                }
            }
        };
    }

    exhaustive_roundtrip_tier_test!(
        roundtrip_is_exhaustive_for_first_4096_ids_in_tier_3,
        3,
        4096
    );
    exhaustive_roundtrip_tier_test!(
        roundtrip_is_exhaustive_for_first_4096_ids_in_tier_4,
        4,
        4096
    );
    exhaustive_roundtrip_tier_test!(
        roundtrip_is_exhaustive_for_first_4096_ids_in_tier_5,
        5,
        4096
    );
    exhaustive_roundtrip_tier_test!(
        roundtrip_is_exhaustive_for_first_4096_ids_in_tier_6,
        6,
        4096
    );

    macro_rules! unique_prefix_tier_test {
        ($name:ident, $code_len:expr, $count:expr) => {
            #[test]
            fn $name() {
                let ids = (0_u64..$count)
                    .map(|local_id| {
                        encode_local_id($code_len, local_id).expect("encoding must succeed")
                    })
                    .collect::<Vec<_>>();
                let unique = ids.iter().collect::<HashSet<_>>();
                assert_eq!(unique.len(), ids.len());
            }
        };
    }

    unique_prefix_tier_test!(public_ids_are_unique_for_first_2048_ids_in_tier_3, 3, 2048);
    unique_prefix_tier_test!(public_ids_are_unique_for_first_2048_ids_in_tier_4, 4, 2048);
    unique_prefix_tier_test!(public_ids_are_unique_for_first_2048_ids_in_tier_5, 5, 2048);
    unique_prefix_tier_test!(public_ids_are_unique_for_first_2048_ids_in_tier_6, 6, 2048);

    #[test]
    fn encoded_ids_only_use_base56_alphabet() {
        for code_len in [3_u8, 4, 5, 6] {
            for local_id in 0_u64..512 {
                let encoded = encode_local_id(code_len, local_id).expect("encoding must succeed");
                assert_eq!(encoded.len(), usize::from(code_len));
                for byte in encoded.bytes() {
                    assert!(
                        BASE56_ALPHABET.contains(&byte),
                        "unexpected byte {byte} in {encoded}"
                    );
                }
            }
        }
    }
}
