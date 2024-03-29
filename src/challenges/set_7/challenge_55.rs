use crate::digest::md4::*;
use crate::util::{clear_bit, is_bit_equal, is_bit_set, set_bit, set_bit_equal};

pub struct MD4CollisionGenerator {
    states: Vec<[u32; 4]>,
}

impl MD4CollisionGenerator {
    pub fn new() -> Self {
        Self {
            states: vec![[A, B, C, D]],
        }
    }

    pub fn generate(&mut self, message_len: usize) -> (Vec<u8>, Vec<u8>) {
        let message = std::iter::repeat_with(rand::random::<u8>)
            .take(message_len)
            .collect::<Vec<u8>>();
        // message.extend(get_padding(message_len));

        self.generate_from(&message)
    }

    fn split_into_blocks(message: &Vec<u8>) -> Vec<[u32; 16]> {
        // Split into 32-bit words
        let words = message
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>();

        // Split into 16-word blocks
        words
            .chunks(16)
            .map(|chunk| chunk.try_into().unwrap())
            .collect::<Vec<[u32; 16]>>()
    }

    fn blocks_into_message(blocks: &[[u32; 16]]) -> Vec<u8> {
        blocks
            .iter()
            .flat_map(|block| block.map(|value| u32::to_le_bytes(value)))
            .flatten()
            .collect::<Vec<u8>>()
    }

    fn generate_from(&mut self, message: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut blocks = Self::split_into_blocks(message);

        println!("blocks: {:x?}", blocks);
        for mut block in blocks.iter_mut() {
            self.apply_single_step_modifications(&mut block);

            self.apply_multi_step_modifications(&mut block);
        }

        println!("blocks: {:x?}", blocks);

        let output = Self::blocks_into_message(&blocks);

        println!("output: {:x?}", output);

        (output, Vec::new())
    }

    fn round_1(&mut self, block: &[u32]) {
        let shifts = [3, 7, 11, 19];
        let state_indices = [0, 3, 2, 1];
        for block_index in 0..=15 {
            if block_index % 4 == 0 {
                // Push the current state
                self.states.push(*self.states.last().unwrap());
            }
            let states_index = self.states.len() - 1;
            let state_index = state_indices[block_index % 4];
            let shift = shifts[block_index % 4];
            self.states[states_index][state_index] =
                self.apply_f(states_index, state_index, block[block_index], shift);
        }
    }

    fn round_2(&mut self, block: &[u32]) {
        let shifts = [3, 5, 9, 13];
        let state_indices = [0, 3, 2, 1];
        for index in 0..=15 {
            if index % 4 == 0 {
                // Push the current state
                self.states.push(*self.states.last().unwrap());
            }
            let states_index = self.states.len() - 1;
            let block_index = if index < 15 { (index * 4) % 15 } else { 15 };
            let state_index = state_indices[index % 4];
            let shift = shifts[index % 4];
            self.states[states_index][state_index] =
                self.apply_g(states_index, state_index, block[block_index], shift);
        }
    }

    fn round_3(&mut self, block: &[u32]) {
        let block_indices = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        let shifts = [3, 9, 11, 15];
        let state_indices = [0, 3, 2, 1];
        for index in 0..=15 {
            if index % 4 == 0 {
                // Push the current state
                self.states.push(*self.states.last().unwrap());
            }
            let states_index = self.states.len() - 1;
            let block_index = block_indices[index];
            let state_index = state_indices[index % 4];
            let shift = shifts[index % 4];
            self.states[states_index][state_index] =
                self.apply_h(states_index, state_index, block[block_index], shift);
        }
    }

    fn apply_single_step_modifications(&mut self, mut block: &mut [u32; 16]) {
        // Push the current state - this will be a1, b1, c1, d1
        self.states.push(*self.states.last().unwrap());

        // Adjust a1, d1, c1, b1
        let states_index = self.states.len() - 1;
        self.apply_bit_change(states_index, 0, &mut block, 0, 3);
        self.apply_bit_change(states_index, 3, &mut block, 1, 7);
        self.apply_bit_change(states_index, 2, &mut block, 2, 11);
        self.apply_bit_change(states_index, 1, &mut block, 3, 19);

        // Push the current state
        self.states.push(*self.states.last().unwrap());

        // Adjust a2, d2, c2, b2
        let states_index = self.states.len() - 1;
        self.apply_bit_change(states_index, 0, &mut block, 4, 3);
        self.apply_bit_change(states_index, 3, &mut block, 5, 7);
        self.apply_bit_change(states_index, 2, &mut block, 6, 11);
        self.apply_bit_change(states_index, 1, &mut block, 7, 19);

        // Push the current state
        self.states.push(*self.states.last().unwrap());

        // Adjust a3, d3, c3, b3
        let states_index = self.states.len() - 1;
        self.apply_bit_change(states_index, 0, &mut block, 8, 3);
        self.apply_bit_change(states_index, 3, &mut block, 9, 7);
        self.apply_bit_change(states_index, 2, &mut block, 10, 11);
        self.apply_bit_change(states_index, 1, &mut block, 11, 19);

        // Push the current state
        self.states.push(*self.states.last().unwrap());

        // Adjust a4, d4, c4, b4
        let states_index = self.states.len() - 1;
        self.apply_bit_change(states_index, 0, &mut block, 12, 3);
        self.apply_bit_change(states_index, 3, &mut block, 13, 7);
        self.apply_bit_change(states_index, 2, &mut block, 14, 11);
        self.apply_bit_change(states_index, 1, &mut block, 15, 19);
    }

    fn apply_bit_change(
        &mut self,
        states_index: usize,
        state_index: usize,
        block: &mut [u32; 16],
        block_index: usize,
        shift: u32,
    ) {
        // Apply f from MD4
        self.states[states_index][state_index] =
            self.apply_f(states_index, state_index, block[block_index], shift);

        // Fix the bits
        self.adjust_f_bits(block_index);

        // Invert and set the appropriate block
        block[block_index] = self.invert_f(states_index, state_index, shift);
    }

    fn apply_f(&mut self, states_index: usize, state_index: usize, word: u32, shift: u32) -> u32 {
        // Syntactic sugar
        let state_len = self.states[0].len();
        let a = self.states[states_index][state_index];
        let b = self.states[states_index][(state_index + 1) % state_len];
        let c = self.states[states_index][(state_index + 2) % state_len];
        let d = self.states[states_index][(state_index + 3) % state_len];

        // Apply f from MD4
        a.wrapping_add(f(&b, &c, &d))
            .wrapping_add(word)
            .rotate_left(shift)
    }

    fn invert_f(&mut self, states_index: usize, state_index: usize, shift: u32) -> u32 {
        // Syntactic sugar
        let state_len = self.states[0].len();
        let a = self.states[states_index - 1][state_index];
        let b = self.states[states_index][(state_index + 1) % state_len];
        let c = self.states[states_index][(state_index + 2) % state_len];
        let d = self.states[states_index][(state_index + 3) % state_len];

        self.states[states_index][state_index]
            .rotate_right(shift)
            .wrapping_sub(a)
            .wrapping_sub(f(&b, &c, &d))
    }

    fn adjust_f_bits(&mut self, block_index: usize) {
        match block_index {
            0 => self.adjust_a1(),
            1 => self.adjust_d1(),
            2 => self.adjust_c1(),
            3 => self.adjust_b1(),
            4 => self.adjust_a2(),
            5 => self.adjust_d2(),
            6 => self.adjust_c2(),
            7 => self.adjust_b2(),
            8 => self.adjust_a3(),
            9 => self.adjust_d3(),
            10 => self.adjust_c3(),
            11 => self.adjust_b3(),
            12 => self.adjust_a4(),
            13 => self.adjust_d4(),
            14 => self.adjust_c4(),
            15 => self.adjust_b4(),
            _ => unreachable!(),
        }
    }

    fn apply_multi_step_modifications(&mut self, mut block: &mut [u32; 16]) {
        // Push the current state
        self.states.push(*self.states.last().unwrap());

        self.apply_a5_changes(&mut block);
    }

    fn apply_g(&mut self, states_index: usize, state_index: usize, word: u32, shift: u32) -> u32 {
        // Syntactic sugar
        let state_len = self.states[0].len();
        let a = self.states[states_index][state_index];
        let b = self.states[states_index][(state_index + 1) % state_len];
        let c = self.states[states_index][(state_index + 2) % state_len];
        let d = self.states[states_index][(state_index + 3) % state_len];

        a.wrapping_add(g(&b, &c, &d))
            .wrapping_add(word)
            .wrapping_add(G)
            .rotate_left(shift)
    }

    fn invert_g(&mut self, states_index: usize, state_index: usize, shift: u32) -> u32 {
        // Syntactic sugar
        let state_len = self.states[0].len();
        let a = self.states[states_index - 1][state_index];
        let b = self.states[states_index][(state_index + 1) % state_len];
        let c = self.states[states_index][(state_index + 2) % state_len];
        let d = self.states[states_index][(state_index + 3) % state_len];

        self.states[states_index][state_index]
            .rotate_right(shift)
            .wrapping_sub(G)
            .wrapping_sub(a)
            .wrapping_sub(g(&b, &c, &d))
    }

    fn apply_h(&mut self, states_index: usize, state_index: usize, value: u32, shift: u32) -> u32 {
        // Syntactic sugar
        let state_len = self.states[0].len();
        let a = &self.states[states_index][state_index];
        let b = &self.states[states_index][(state_index + 1) % state_len];
        let c = &self.states[states_index][(state_index + 2) % state_len];
        let d = &self.states[states_index][(state_index + 3) % state_len];

        a.wrapping_add(h(b, c, d))
            .wrapping_add(value)
            .wrapping_add(0x6ed9eba1u32)
            .rotate_left(shift)
    }

    // fn adjust_g_bits(&mut self, block_index: usize) {
    //     match block_index {
    //         0 => {
    //             for bit_number in [18, 25, 26, 28, 31] {
    //                 if !is_bit_equal(self.state[0], self.state[2], bit_number) {
    //                     self.state[0] = set_bit_equal(self.state[0], self.state[2], bit_number);
    //                 }
    //             }
    //         }
    //     }
    // }

    fn adjust_a1(&mut self) {
        println!("Setting a1, bit 6, to b0 bit 6");
        // a[1][6] = b[0][6]
        self.states[1][0] = set_bit_equal(self.states[1][0], self.states[0][1], 6);
    }

    fn adjust_d1(&mut self) {
        // d[1][6] = 0
        self.states[1][3] = clear_bit(self.states[1][3], 6);

        // d[1][7] = a[1][7]
        self.states[1][3] = set_bit_equal(self.states[1][3], self.states[1][0], 7);

        // d[1][10] = a[1][10]
        self.states[1][3] = set_bit_equal(self.states[1][3], self.states[1][0], 10);
    }

    fn adjust_c1(&mut self) {
        // c[1][6] = 1
        self.states[1][2] = set_bit(self.states[1][2], 6);

        // c[1][7] = 1
        self.states[1][2] = set_bit(self.states[1][2], 7);

        // c[1][10] = 0
        self.states[1][2] = clear_bit(self.states[1][2], 10);

        // c[1][25] = d[1][25]
        self.states[1][2] = set_bit_equal(self.states[1][2], self.states[1][3], 25);
    }

    fn adjust_b1(&mut self) {
        // b[1][6] = 1
        self.states[1][1] = set_bit(self.states[1][1], 6);

        // b[1][7] = 0
        self.states[1][1] = clear_bit(self.states[1][1], 7);

        // b[1][10] = 0
        self.states[1][1] = clear_bit(self.states[1][1], 10);

        // b[1][25] = 0
        self.states[1][1] = clear_bit(self.states[1][1], 25);
    }

    fn adjust_a2(&mut self) {
        // a[2][7] = 1
        self.states[2][0] = set_bit(self.states[2][0], 7);

        // a[2][10] = 1
        self.states[2][0] = set_bit(self.states[2][0], 10);

        // a[2][25] = 0
        self.states[2][0] = clear_bit(self.states[2][0], 25);

        // a[2][13] = b[1][13]
        self.states[2][0] = set_bit_equal(self.states[2][0], self.states[1][1], 13);
    }

    fn adjust_d2(&mut self) {
        // d[2][13] = 0
        self.states[2][3] = clear_bit(self.states[2][3], 13);

        // d[2][18] = a[2][18]
        self.states[2][3] = set_bit_equal(self.states[2][3], self.states[2][0], 18);

        // d[2][19] = a[2][19]
        self.states[2][3] = set_bit_equal(self.states[2][3], self.states[2][0], 19);

        // d[2][20] = a[2][20]
        self.states[2][3] = set_bit_equal(self.states[2][3], self.states[2][0], 20);

        // d[2][21] = a[2][21]
        self.states[2][3] = set_bit_equal(self.states[2][3], self.states[2][0], 21);

        // d[2][25] = 1
        self.states[2][3] = set_bit(self.states[2][3], 25);
    }

    fn adjust_c2(&mut self) {
        // c[2][12] = d[2][12]
        self.states[2][2] = set_bit_equal(self.states[2][2], self.states[2][0], 12);

        // c[2][13] = 0
        self.states[2][2] = clear_bit(self.states[2][2], 13);

        // c[2][14] = d[2][14]
        self.states[2][2] = set_bit_equal(self.states[2][2], self.states[2][0], 14);

        // c[2][18] = 0
        self.states[2][2] = clear_bit(self.states[2][2], 18);

        // c[2][19] = 0
        self.states[2][2] = clear_bit(self.states[2][2], 19);

        // c[2][20] = 1
        self.states[2][2] = set_bit(self.states[2][2], 20);

        // c[2][21] = 0
        self.states[2][2] = clear_bit(self.states[2][2], 21);
    }

    fn adjust_b2(&mut self) {
        // b[2][12] = 1
        self.states[2][1] = set_bit(self.states[2][1], 12);

        // b[2][13] = 1
        self.states[2][1] = set_bit(self.states[2][1], 13);

        // b[2][14] = 0
        self.states[2][1] = clear_bit(self.states[2][1], 14);

        // b[2][16] = c[2][16]
        self.states[2][1] = set_bit_equal(self.states[2][1], self.states[2][2], 16);

        // b[2][18] = 0
        self.states[2][1] = clear_bit(self.states[2][1], 18);

        // b[2][19] = 0
        self.states[2][1] = clear_bit(self.states[2][1], 19);

        // b[2][20] = 0
        self.states[2][1] = clear_bit(self.states[2][1], 20);

        // b[2][21] = 0
        self.states[2][1] = clear_bit(self.states[2][1], 21);
    }

    fn adjust_a3(&mut self) {
        // a[3][12] = 1
        self.states[3][0] = set_bit(self.states[3][0], 12);

        // a[3][13] = 1
        self.states[3][0] = set_bit(self.states[3][0], 13);

        // a[3][14] = 1
        self.states[3][0] = set_bit(self.states[3][0], 14);

        // a[3][16] = 0
        self.states[3][0] = clear_bit(self.states[3][0], 16);

        // a[3][18] = 0
        self.states[3][0] = clear_bit(self.states[3][0], 18);

        // a[3][19] = 0
        self.states[3][0] = clear_bit(self.states[3][0], 19);

        // a[3][20] = 0
        self.states[3][0] = clear_bit(self.states[3][0], 20);

        // a[3][22] = b[2][22]
        self.states[3][0] = set_bit_equal(self.states[3][0], self.states[2][1], 22);

        // a[3][21] = 1
        self.states[3][0] = set_bit(self.states[3][0], 21);

        // a[3][25] = b[2][25]
        self.states[3][0] = set_bit_equal(self.states[3][0], self.states[2][1], 25);
    }

    fn adjust_d3(&mut self) {
        // d[3][12] = 1
        self.states[3][3] = set_bit(self.states[3][3], 12);

        // d[3][13] = 1
        self.states[3][3] = set_bit(self.states[3][3], 13);

        // d[3][14] = 1
        self.states[3][3] = set_bit(self.states[3][3], 14);

        // d[3][16] = 0
        self.states[3][3] = clear_bit(self.states[3][3], 16);

        // d[3][19] = 0
        self.states[3][3] = clear_bit(self.states[3][3], 19);

        // d[3][20] = 1
        self.states[3][3] = set_bit(self.states[3][3], 20);

        // d[3][21] = 1
        self.states[3][3] = set_bit(self.states[3][3], 21);

        // d[3][22] = 0
        self.states[3][3] = clear_bit(self.states[3][3], 22);

        // d[3][25] = 1
        self.states[3][3] = set_bit(self.states[3][3], 25);

        // d[3][29] = a[3][29]
        self.states[3][3] = set_bit_equal(self.states[3][3], self.states[3][0], 29);
    }

    fn adjust_c3(&mut self) {
        // c[3][16] = 1
        self.states[3][2] = set_bit(self.states[3][2], 16);

        // c[3][19] = 0
        self.states[3][2] = clear_bit(self.states[3][2], 19);

        // c[3][20] = 0
        self.states[3][2] = clear_bit(self.states[3][2], 20);

        // c[3][21] = 0
        self.states[3][2] = clear_bit(self.states[3][2], 21);

        // c[3][22] = 0
        self.states[3][2] = clear_bit(self.states[3][2], 22);

        // c[3][25] = 0
        self.states[3][2] = clear_bit(self.states[3][2], 25);

        // c[3][29] = 1
        self.states[3][2] = set_bit(self.states[3][2], 29);

        // c[3][31] = d[3][31]
        self.states[3][2] = set_bit_equal(self.states[3][2], self.states[3][3], 31);
    }

    fn adjust_b3(&mut self) {
        // b[3][19] = 0
        self.states[3][1] = clear_bit(self.states[3][1], 19);

        // b[3][20] = 1
        self.states[3][1] = set_bit(self.states[3][1], 20);

        // b[3][21] = 1
        self.states[3][1] = set_bit(self.states[3][1], 21);

        // b[3][22] = c[3][22]
        self.states[3][1] = set_bit_equal(self.states[3][1], self.states[3][2], 22);

        // b[3][29] = 0
        self.states[3][1] = clear_bit(self.states[3][1], 29);

        // b[3][31] = 0
        self.states[3][1] = clear_bit(self.states[3][1], 31);
    }

    fn adjust_a4(&mut self) {
        // a[4][22] = 0
        self.states[4][0] = clear_bit(self.states[4][0], 22);

        // a[4][25] = 0
        self.states[4][0] = clear_bit(self.states[4][0], 25);

        // a[4][26] = b[3][26]
        self.states[4][0] = set_bit_equal(self.states[4][0], self.states[3][1], 26);

        // a[4][28] = b[3][28]
        self.states[4][0] = set_bit_equal(self.states[4][0], self.states[3][1], 28);

        // a[4][29] = 1
        self.states[4][0] = set_bit(self.states[4][0], 29);

        // a[4][31] = 0
        self.states[4][0] = clear_bit(self.states[4][0], 31);
    }

    fn adjust_d4(&mut self) {
        // d[4][22] = 0
        self.states[4][3] = clear_bit(self.states[4][3], 22);

        // d[4][25] = 0
        self.states[4][3] = clear_bit(self.states[4][3], 25);

        // d[4][26] = 1
        self.states[4][3] = set_bit(self.states[4][3], 26);

        // d[4][28] = 1
        self.states[4][3] = set_bit(self.states[4][3], 28);

        // d[4][29] = 0
        self.states[4][3] = clear_bit(self.states[4][3], 29);

        // d[4][31] = 1
        self.states[4][3] = set_bit(self.states[4][3], 31);
    }

    fn adjust_c4(&mut self) {
        // c[4][18] = d[4][18]
        self.states[4][2] = set_bit_equal(self.states[4][2], self.states[4][3], 18);

        // c[4][22] = 1
        self.states[4][2] = set_bit(self.states[4][2], 22);

        // c[4][25] = 1
        self.states[4][2] = set_bit(self.states[4][2], 25);

        // c[4][26] = 0
        self.states[4][2] = clear_bit(self.states[4][2], 26);

        // c[4][28] = 0
        self.states[4][2] = clear_bit(self.states[4][2], 28);

        // c[4][29] = 0
        self.states[4][2] = clear_bit(self.states[4][2], 29);
    }

    fn adjust_b4(&mut self) {
        // b[4][18] = 0
        self.states[4][1] = clear_bit(self.states[4][1], 18);

        // b[4][22] = 1
        self.states[4][1] = set_bit(self.states[4][1], 22);

        // b[4][25] = c[4][25]
        self.states[4][1] = set_bit_equal(self.states[4][1], self.states[4][2], 25);

        // b[4][26] = 1
        self.states[4][1] = set_bit(self.states[4][1], 26);

        // b[4][28] = 1
        self.states[4][1] = set_bit(self.states[4][1], 28);

        // b[4][29] = 0
        self.states[4][1] = clear_bit(self.states[4][1], 29);
    }

    fn apply_a5_changes(&mut self, block: &mut [u32; 16]) {
        // Apply g from MD4
        self.states[5][0] = self.apply_g(5, 0, block[0], 3);

        // Check and see if any changes need to be made
        self.states[5][0] = set_bit_equal(self.states[5][0], self.states[4][2], 18);
        self.states[5][0] = set_bit(self.states[5][0], 25);
        self.states[5][0] = clear_bit(self.states[5][0], 26);
        self.states[5][0] = set_bit(self.states[5][0], 28);
        self.states[5][0] = set_bit(self.states[5][0], 31);

        assert!(is_bit_equal(self.states[5][0], self.states[4][2], 18));
        assert!(is_bit_set(self.states[5][0], 25));
        assert!(!is_bit_set(self.states[5][0], 26));
        assert!(is_bit_set(self.states[5][0], 28));
        assert!(is_bit_set(self.states[5][0], 31));

        // Changes have been made, first invert the changes to get the first block
        block[0] = self.invert_g(5, 0, 3);

        // Reapply single-step change to block 0
        // self.apply_bit_change(1, 0, block, 0, 3);

        // Update a1 from the changes
        self.states[1][0] = self.apply_f(0, 0, block[0], 3);

        // Update the next four blocks from the changes
        block[1] = self.invert_f(1, 3, 7);
        block[2] = self.invert_f(1, 2, 11);
        block[3] = self.invert_f(1, 1, 19);
        block[4] = self.invert_f(2, 0, 3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invert_f() {
        let mut generator = MD4CollisionGenerator::new();
        let block = rand::random::<u32>();
        generator.states.push(generator.states[0]);
        generator.states[1][0] = generator.apply_f(0, 0, block, 3);
        let output = generator.invert_f(1, 0, 3);
        assert_eq!(block, output);
    }

    #[test]
    fn test_invert_g() {
        let mut generator = MD4CollisionGenerator::new();
        let block = rand::random::<u32>();
        generator.states.push(generator.states[0]);
        generator.states[1][0] = generator.apply_g(1, 0, block, 3);
        let output = generator.invert_g(1, 0, 3);
        assert_eq!(block, output);
    }

    #[test]
    fn test_blocks_to_messages() {
        let message = std::iter::repeat_with(rand::random::<u8>)
            .take(64)
            .collect::<Vec<u8>>();
        let blocks = MD4CollisionGenerator::split_into_blocks(&message);
        let output = MD4CollisionGenerator::blocks_into_message(&blocks);
        assert_eq!(message, output);
    }

    #[test]
    fn test_round_1_changes() {
        let mut generator = MD4CollisionGenerator::new();
        println!("Generating message");
        let (output, _) = generator.generate(64);

        println!("Testing message");
        let mut tester = MD4CollisionGenerator::new();
        let blocks = MD4CollisionGenerator::split_into_blocks(&output);
        for block in blocks {
            tester.round_1(&block);
            tester.round_2(&block);
            tester.round_3(&block);
        }

        assert!(is_bit_equal(tester.states[5][0], tester.states[4][2], 18));
        assert!(is_bit_set(tester.states[5][0], 25));
        assert!(!is_bit_set(tester.states[5][0], 26));
        assert!(is_bit_set(tester.states[5][0], 28));
        assert!(is_bit_set(tester.states[5][0], 31));
        assert!(is_bit_equal(tester.states[1][0], tester.states[0][1], 6));
        assert!(!is_bit_set(tester.states[1][3], 6));
        assert!(is_bit_equal(tester.states[1][3], tester.states[1][0], 7));
        assert!(is_bit_equal(tester.states[1][3], tester.states[1][0], 10));
    }

    #[test]
    fn challenge_55() {}
}
