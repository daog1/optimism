// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { CommonTest } from "./CommonTest.t.sol";
import { MIPS } from "src/cannon/MIPS.sol";
import { PreimageOracle } from "src/cannon/PreimageOracle.sol";
import { console2 as console } from "forge-std/console2.sol";

contract MIPS_Test is CommonTest {
    MIPS internal mips;
    PreimageOracle internal oracle;

    function setUp() public virtual override {
        super.setUp();
        oracle = new PreimageOracle();
        mips = new MIPS();
        vm.store(address(mips), 0x0, bytes32(abi.encode(address(oracle))));
        vm.label(address(oracle), "PreimageOracle");
        vm.label(address(mips), "MIPS");
    }

    function test_step_abi_succeeds() external {
        uint32[32] memory registers;
        registers[16] = 0xbfff0000;
        MIPS.State memory state = MIPS.State({
            memRoot: hex"30be14bdf94d7a93989a6263f1e116943dc052d584730cae844bf330dfddce2f",
            preimageKey: bytes32(0),
            preimageOffset: 0,
            pc: 4,
            nextPC: 8,
            lo: 0,
            hi: 0,
            heap: 0,
            exitCode: 0,
            exited: false,
            step: 1,
            registers: registers
        });
        bytes memory proof = hex"3c10bfff3610fff0341100013c08ffff3508fffd34090003010950202d420001ae020008ae11000403e000080000000000000000000000000000000000000000ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d3021ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85e58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a193440eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968ffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f839867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756afcefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0f9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5f8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf8923490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99cc1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8beccda7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d22733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981fe1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0b46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0c65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2f4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd95a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e3774df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652cdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618db8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        bytes32 postState = mips.step(encodeState(state), proof);
        assertTrue(postState != bytes32(0));
    }

    function test_add_succeeds() external {
        uint32 pc = 0x0;
        uint32 insn = 0x2324020; // add t0, s1, s2
        (bytes32 memRoot, bytes memory proof) = ffi.getCannonMemoryProof(pc, insn);

        uint8 t0_reg = 8;
        uint16 s1 = 4;
        uint16 s2 = 9;
        uint32[32] memory registers;
        registers[t0_reg] = 1;
        registers[17] = s1;
        registers[18] = s2;

        MIPS.State memory state = MIPS.State({
            memRoot: memRoot,
            preimageKey: bytes32(0),
            preimageOffset: 0,
            pc: 0,
            nextPC: 4,
            lo: 0,
            hi: 0,
            heap: 0,
            exitCode: 0,
            exited: false,
            step: 1,
            registers: registers
        });
        bytes memory encodedState = encodeState(state);

        MIPS.State memory expect = state;
        expect.pc = state.nextPC;
        expect.nextPC += 4;
        expect.step += 1;
        expect.registers[t0_reg] = s1 + s2;

        bytes32 postState = mips.step(encodedState, proof);
        assertTrue(postState == outputState(expect), "unexpected post state");
    }

    function test_jump_succeeds() external {
        uint32 pc = 0x0;
        uint16 label = 0x2;
        uint32 insn = uint32(0x08_00_00_00) | label; // j label
        (bytes32 memRoot, bytes memory proof) = ffi.getCannonMemoryProof(pc, insn);

        MIPS.State memory state;
        state.pc = 0;
        state.nextPC = 4;
        state.memRoot = memRoot;

        MIPS.State memory expect;
        expect.memRoot = state.memRoot;
        expect.pc = state.nextPC;
        expect.nextPC = label << 2;
        expect.step = state.step + 1;

        bytes32 postState = mips.step(encodeState(state), proof);
        assertTrue(postState == outputState(expect), "unexpected post state");
    }

    function test_jal_succeeds() external {
        uint32 pc = 0x0;
        uint16 label = 0x2;
        uint32 insn = uint32(0x0c_00_00_00) | label; // jal label
        (bytes32 memRoot, bytes memory proof) = ffi.getCannonMemoryProof(pc, insn);

        MIPS.State memory state;
        state.pc = 0;
        state.nextPC = 4;
        state.memRoot = memRoot;

        MIPS.State memory expect;
        expect.memRoot = state.memRoot;
        expect.pc = state.nextPC;
        expect.nextPC = label << 2;
        expect.step = state.step + 1;
        expect.registers[31] = state.pc + 8;

        bytes32 postState = mips.step(encodeState(state), proof);
        assertTrue(postState == outputState(expect), "unexpected post state");
    }

    function test_preimage_read_succeeds() external {
        uint32 pc = 0x0;
        uint32 insn = 0x0000000c; // syscall
        uint32 a1 = 0x4;
        uint32 a1_val = 0x0000abba;
        (bytes32 memRoot, bytes memory proof) = ffi.getCannonMemoryProof(pc, insn, a1, a1_val);

        uint32[32] memory registers;
        registers[2] = 4003; // read syscall
        registers[4] = 5; // fd
        registers[5] = a1; // addr
        registers[6] = 4; // count

        MIPS.State memory state = MIPS.State({
            memRoot: memRoot,
            preimageKey: bytes32(uint256(1) << 248 | 0x01),
            preimageOffset: 8, // start reading past the pre-image length prefix
            pc: pc,
            nextPC: pc + 4,
            lo: 0,
            hi: 0,
            heap: 0,
            exitCode: 0,
            exited: false,
            step: 1,
            registers: registers
        });
        bytes memory encodedState = encodeState(state);

        // prime the pre-image oracle
        bytes32 word = bytes32(uint256(0xdeadbeef) << 224);
        uint8 size = 4;
        uint8 partOffset = 8;
        oracle.loadLocalData(uint256(state.preimageKey), word, size, partOffset);

        MIPS.State memory expect = state;
        expect.preimageOffset += 4;
        expect.pc = state.nextPC;
        expect.nextPC += 4;
        expect.step += 1;
        expect.registers[2] = 4; // return
        expect.registers[7] = 0; // errno
        // recompute merkle root of written pre-image
        (expect.memRoot,) = ffi.getCannonMemoryProof(pc, insn, a1, 0xdeadbeef);

        bytes32 postState = mips.step(encodedState, proof);
        assertTrue(postState == outputState(expect), "unexpected post state");
    }

    function test_preimage_write_succeeds() external {
        uint32 pc = 0x0;
        uint32 insn = 0x0000000c; // syscall
        uint32 a1 = 0x4;
        uint32 a1_val = 0x0000abba;
        (bytes32 memRoot, bytes memory proof) = ffi.getCannonMemoryProof(pc, insn, a1, a1_val);

        uint32[32] memory registers;
        registers[2] = 4004; // write syscall
        registers[4] = 6; // fd
        registers[5] = a1; // addr
        registers[6] = 4; // count

        MIPS.State memory state = MIPS.State({
            memRoot: memRoot,
            preimageKey: bytes32(0),
            preimageOffset: 1,
            pc: pc,
            nextPC: 4,
            lo: 0,
            hi: 0,
            heap: 0,
            exitCode: 0,
            exited: false,
            step: 1,
            registers: registers
        });
        bytes memory encodedState = encodeState(state);

        MIPS.State memory expect = state;
        expect.preimageOffset = 0; // preimage write resets offset
        expect.pc = state.nextPC;
        expect.nextPC += 4;
        expect.step += 1;
        expect.preimageKey = bytes32(uint256(0xabba));
        expect.registers[2] = 4; // return
        expect.registers[7] = 0; // errno

        bytes32 postState = mips.step(encodedState, proof);
        assertTrue(postState == outputState(expect), "unexpected post state");
    }

    function test_mmap_succeeds() external {
        uint32 insn = 0x0000000c; // syscall
        (bytes32 memRoot, bytes memory proof) = ffi.getCannonMemoryProof(0, insn);

        MIPS.State memory state;
        state.memRoot = memRoot;
        state.nextPC = 4;
        state.registers[2] = 4090; // mmap syscall
        state.registers[4] = 0x0; // a0
        state.registers[5] = 4095; // a1
        bytes memory encodedState = encodeState(state);

        MIPS.State memory expect = state;
        // assert page allocation is aligned to 4k
        expect.step += 1;
        expect.pc = state.nextPC;
        expect.nextPC += 4;
        expect.heap += 4096;
        expect.registers[2] = 0; // return old heap

        bytes32 postState = mips.step(encodedState, proof);
        assertTrue(postState == outputState(expect), "unexpected post state");
    }

    function test_illegal_instruction_fails() external {
        uint32 illegal_insn = 0xFF_FF_FF_FF;
        // the illegal instruction is partially decoded as containing a memory operand
        // so we stuff random data to the expected address
        uint32 addr = 0xFF_FF_FF_FC; // 4-byte aligned ff..ff
        (bytes32 memRoot, bytes memory proof) = ffi.getCannonMemoryProof(0, illegal_insn, addr, 0);

        MIPS.State memory state;
        state.memRoot = memRoot;
        bytes memory encodedState = encodeState(state);
        vm.expectRevert("invalid instruction");
        mips.step(encodedState, proof);
    }

    function encodeState(MIPS.State memory state) internal pure returns (bytes memory) {
        bytes memory registers;
        for (uint i = 0; i < state.registers.length; i++) {
            registers = bytes.concat(registers, abi.encodePacked(state.registers[i]));
        }
        return abi.encodePacked(
            state.memRoot,
            state.preimageKey,
            state.preimageOffset,
            state.pc,
            state.nextPC,
            state.lo,
            state.hi,
            state.heap,
            state.exitCode,
            state.exited,
            state.step,
            registers
        );
    }

    function outputState(MIPS.State memory state) internal pure returns (bytes32 out_) {
        bytes memory enc = encodeState(state);
        assembly {
            out_ := keccak256(add(enc, 0x20), 226)
        }
    }
}
