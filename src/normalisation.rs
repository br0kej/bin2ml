/*
Instruction Normalisation
*/
use crate::consts::{
    GENERAL_PURPOSE_32_BIT_REGS, GENERAL_PURPOSE_64_BIT_REGS, MULTI_ARCH_FRAME_POINTERS,
};
use regex::Regex;

// Cross Arch Disasm Normalisation
pub fn normalise_disasm_simple(input: &str, reg_norm: bool) -> String {
    let orig = input.to_owned();
    // Remove commas
    let normalised = orig.replace(',', " ");
    // Replace any cases where there are two spaces with only one
    let normalised = normalised.replace("  ", " ");

    let re = Regex::new(r"(0xffff[0-9a-fA-F]{1,})").unwrap();
    let normalised = re.replace_all(&normalised, "IMM");

    // Immediates used as mem offsets in X86
    let re = Regex::new(r"(0[xX][0-9a-fA-F]{1,3}])").unwrap();
    let normalised = re.replace_all(&normalised, "IMM]");

    // Offsets used in MIPS
    let re = Regex::new(r"(0[xX][0-9a-fA-F]{1,4})\(").unwrap();
    let normalised = re.replace_all(&normalised, "IMM(");

    // Memory addresses
    // This normalisation is very naive. It assume any hex value longer than 0x+4 digits
    // is a memory address.
    let re = Regex::new(r"(0[xX][0-9a-fA-F]{4,})").unwrap();
    let normalised = re.replace_all(&normalised, "MEM");

    // Strings
    let re = Regex::new(r"(str\S*[^!\s][_|s]{0,1})").unwrap();
    let normalised = re.replace_all(&normalised, "STR");

    // c++ funcs
    let re = Regex::new(r"method.*[^!\s]\(*.*(\)|>*)").unwrap();
    let normalised = re.replace_all(&normalised, "FUNC");

    // fcn and sym calls
    let re = Regex::new(r"(fcn|sym).*[^!\s]").unwrap();
    let normalised = re.replace_all(&normalised, "FUNC");

    // obj in brackets
    let re = Regex::new(r"[-]{0,1}[\[]{0,1}obj\S*[\]]{0,1}").unwrap();
    let normalised = re.replace_all(&normalised, "DATA");

    // reloc in brackets
    let re = Regex::new(r"\[reloc\S*\]").unwrap();
    let normalised = re.replace_all(&normalised, "FUNC");

    // Normalise multi byte nops
    let re = Regex::new(r"nop.*").unwrap();
    let normalised = re.replace_all(&normalised, "nop");

    // Register Normalisation
    if reg_norm {
        // Split the disasm into it's parts
        let split: Vec<&str> = normalised.split(' ').filter(|e| !e.is_empty()).collect();
        // Match parts of the split instruction with known regs and apply mask
        let split: Vec<String> = split
            .iter()
            .map(|s| {
                if MULTI_ARCH_FRAME_POINTERS.contains(s) {
                    "fp".to_string()
                }
                // If direct match to a 32 bit reg, replace with reg32
                else if GENERAL_PURPOSE_32_BIT_REGS.contains(s) {
                    "reg32".to_string()
                // If direct match to a 64 bit reg, replace with reg64
                } else if GENERAL_PURPOSE_64_BIT_REGS.contains(s) {
                    "reg64".to_string()
                // If we find a case where a token is surround with brackets - x86/ARM
                } else if s.starts_with('[') && s.ends_with(']') {
                    if GENERAL_PURPOSE_32_BIT_REGS.contains(&&s[1..s.len() - 1]) {
                        "[reg32]".to_string()
                    } else if GENERAL_PURPOSE_64_BIT_REGS.contains(&&s[1..s.len() - 1]) {
                        "[reg64]".to_string()
                    } else {
                        s.to_string()
                    }
                // If we find a case where a token starts with a bracket but does not end
                // it's like a reg + offset pattern in x86 - replace tokens apporiately
                } else if s.starts_with('[') && !s.ends_with(']') {
                    if GENERAL_PURPOSE_32_BIT_REGS.contains(&&s[1..s.len()]) {
                        "[reg32".to_string()
                    } else if GENERAL_PURPOSE_64_BIT_REGS.contains(&&s[1..s.len()]) {
                        "[reg64".to_string()
                    } else {
                        s.to_string()
                    }
                // If we find a case where a reg is timed by a value, split, replace
                // the relevant token and then rebuild string
                } else if s.contains('*') {
                    let mut normalised = Vec::new();
                    let reg: Vec<&str> = s.split('*').collect();
                    for ele in reg {
                        if GENERAL_PURPOSE_64_BIT_REGS.contains(&ele) {
                            normalised.push("reg64");
                        } else {
                            normalised.push(ele);
                        }
                    }
                    normalised.join("*")
                } else {
                    s.to_string()
                }
            })
            .collect();

        split.join(" ")
    } else {
        normalised.to_string()
    }
}

pub fn normalise_esil_simple(input: &str, op_type: &str, reg_norm: bool) -> String {
    let orig = input.to_owned();

    let re = Regex::new(r"(0xffff[0-9a-fA-F]{1,},)").unwrap();
    let normalised = re.replace_all(&orig, "IMM,");

    let re = Regex::new(r"(0[xX][0-9a-fA-F]{1,3},)").unwrap();
    let normalised = re.replace_all(&normalised, "IMM,");

    let re = Regex::new(r"(0[xX][0-9a-fA-F]{4,},)").unwrap();
    let normalised = re.replace_all(&normalised, "MEM,");
    // let n_features = if reduced { 6 } else { 7 };
    let normalised = if op_type == "call" {
        let re = Regex::new(r"([0-9]{4,}?,)").unwrap();
        re.replace_all(&normalised, "FUNC,")
    } else {
        let re = Regex::new(r"([0-9]{4,}?,)").unwrap();
        re.replace_all(&normalised, "DATA,")
    };

    if reg_norm {
        // Split the disasm into it's parts
        let split: Vec<&str> = normalised.split(' ').filter(|e| !e.is_empty()).collect();
        //println!("{:?}", split);
        // Match parts of the split instruction with known regs and apply mask
        let split: Vec<String> = split
            .iter()
            .map(|s| {
                //println!("{}\n", s);
                if GENERAL_PURPOSE_32_BIT_REGS.contains(s) {
                    "reg32".to_string()
                } else if GENERAL_PURPOSE_64_BIT_REGS.contains(s) {
                    "reg64".to_string()
                } else {
                    s.to_string()
                }
            })
            .collect();
        split.join(" ")
    } else {
        normalised.to_string()
    }
}

mod tests {
    use super::normalise_esil_simple;
    use crate::normalisation::normalise_disasm_simple;

    // Helper Normalisation Functions
    #[allow(dead_code)]
    fn normalise_esil(input: &str, op_type: &str, norm_regs: bool) -> String {
        let ins: String = String::from(input);
        normalise_esil_simple(&ins, op_type, norm_regs)
    }

    #[allow(dead_code)]
    fn normalise_disasm(input: &str, norm_regs: bool) -> String {
        let ins: String = String::from(input);
        normalise_disasm_simple(&ins, norm_regs)
    }

    #[test]
    fn test_esil_imm() {
        assert_eq!(
            normalise_esil("0x30,rbp,-,[8],rax,=", "not_call", false),
            "IMM,rbp,-,[8],rax,="
        );
        assert_eq!(
            normalise_esil("0x8,rbp,-,[8],rcx,=", "not_call", false),
            "IMM,rbp,-,[8],rcx,="
        );
        assert_eq!(
            normalise_esil("0x74,rcx,+,[4],rdx,=", "not_call", false),
            "IMM,rcx,+,[4],rdx,="
        );
    }

    #[test]
    fn test_esil_big_mem() {
        let normalised_ins = normalise_esil("rcx,rax,-=,rcx,0x8000000000000000,-,!,63,$o,^,of,:=,63,$s,sf,:=,$z,zf,:=,$p,pf,:=,64,$b,cf,:=,3,$b,af,:=", "not_call", false);
        assert_eq!(normalised_ins, "rcx,rax,-=,rcx,MEM,-,!,63,$o,^,of,:=,63,$s,sf,:=,$z,zf,:=,$p,pf,:=,64,$b,cf,:=,3,$b,af,:=");
    }

    #[test]
    fn test_esil_normal_mem() {
        assert_eq!(
            normalise_esil("0x70d388,rcx,8,*,+,[8],rcx,=", "not_call", false),
            "MEM,rcx,8,*,+,[8],rcx,="
        );
        assert_eq!(
            normalise_esil("0x2e822a,rip,+,[8],rax,=", "not_call", false),
            "MEM,rip,+,[8],rax,="
        );
        assert_eq!(
            normalise_esil("0x6fde68,rcx,8,*,+,[8],rcx,=", "not_call", false),
            "MEM,rcx,8,*,+,[8],rcx,="
        )
    }

    #[test]
    fn test_esil_2s_compliment_indexing() {
        assert_eq!(
            normalise_esil(
                "eax,rax,^,0xffffffff,&,rax,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:=",
                "not_call",
                false
            ),
            "eax,rax,^,IMM,&,rax,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:="
        );
        assert_eq!(
            normalise_esil(
                "ecx,rcx,^,0xffffffff,&,rcx,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:=",
                "not call",
                false
            ),
            "ecx,rcx,^,IMM,&,rcx,=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:="
        )
    }

    #[test]
    fn test_esil_func_call() {
        assert_eq!(
            normalise_esil("4269168,rip,8,rsp,-=,rsp,=[8],rip,=", "call", false),
            "FUNC,rip,8,rsp,-=,rsp,=[8],rip,="
        )
    }

    #[test]
    fn test_esil_non_func_call() {
        assert_eq!(
            normalise_esil("4269168,rip,8,rsp,-=,rsp,=[8],rip,=", "not_call", false),
            "DATA,rip,8,rsp,-=,rsp,=[8],rip,="
        )
    }

    #[test]
    fn test_reg_norm_arm32() {
        assert_eq!(normalise_esil("r4 r5 = DATA pc := IMM fp - IMM & [4] IMM & r0 = r0 sb | IMM & r0 = 0 r8 = 0 1 r0 & == $z zf := 31 $s nf := zf ! ?{ DATA pc := } ip 1 + [1] r0 = ip 1 + ip = 0 r0 == $z zf := 31 $s nf := 32 $b ! cf := 31 $o vf := zf ?{ DATA pc := } IMM fp - IMM & [4] IMM & r0 = r0 0 + [1] r0 = -1 0 ^ IMM & r1 = 0 r0 == $z zf := 31 $s nf := 32 $b ! cf := 31 $o vf := r5 r4 = zf ?{ DATA pc := } DATA pc :=", "no_call", true),
                   "reg32 reg32 = DATA pc := IMM fp - IMM & [4] IMM & reg32 = reg32 sb | IMM & reg32 = 0 reg32 = 0 1 reg32 & == $z zf := 31 $s nf := zf ! ?{ DATA pc := } ip 1 + [1] reg32 = ip 1 + ip = 0 reg32 == $z zf := 31 $s nf := 32 $b ! cf := 31 $o vf := zf ?{ DATA pc := } IMM fp - IMM & [4] IMM & reg32 = reg32 0 + [1] reg32 = -1 0 ^ IMM & reg32 = 0 reg32 == $z zf := 31 $s nf := 32 $b ! cf := 31 $o vf := reg32 reg32 = zf ?{ DATA pc := } DATA pc :=");
        assert_eq!(normalise_esil("924 r4 + IMM & [4] IMM & r8 = 0 r4 + IMM & [4] IMM & r5 = r4 r0 = pc lr := FUNC pc := 0 r0 == $z zf := 31 $s nf := 32 $b ! cf := 31 $o vf := zf ?{ DATA pc := } sb r0 = 28 fp", "not_call", true),
                   "924 reg32 + IMM & [4] IMM & reg32 = 0 reg32 + IMM & [4] IMM & reg32 = reg32 reg32 = pc lr := FUNC pc := 0 reg32 == $z zf := 31 $s nf := 32 $b ! cf := 31 $o vf := zf ?{ DATA pc := } sb reg32 = 28 fp")
    }

    #[test]
    fn test_reg_norm_arm64() {
        assert_eq!(normalise_esil("0 MEM w8 & == 31 $s nf := $z zf := 0 cf := 0 vf := xzr 16 sp + DUP tmp = =[8] DATA pc := IMM x22 - x22 = 40 sp + DUP tmp = [8] x8 = x20 x1 = IMM w8 & w0 = pc lr := x19 pc := IMM w0 -1 *", "not_call", true),
                   "0 MEM reg32 & == 31 $s nf := $z zf := 0 cf := 0 vf := xzr 16 sp + DUP tmp = =[8] DATA pc := IMM reg64 - reg64 = 40 sp + DUP tmp = [8] reg64 = reg64 reg64 = IMM reg32 & reg32 = pc lr := reg64 pc := IMM reg32 -1 *")
    }

    // x86 Disasm Normalisation Tests
    #[test]
    fn test_disasm_x86_imm_offset() {
        assert_eq!(
            normalise_disasm("add byte [rax + 0x3d], bh", false),
            "add byte [rax + IMM] bh"
        );
    }

    #[test]
    fn test_disasm_x86_jmp_addr() {
        assert_eq!(normalise_disasm("je 0x11b9", false), "je MEM");
        assert_eq!(normalise_disasm("je 0x121b9", false), "je MEM")
    }

    #[test]
    fn test_disasm_x86_mem_offset() {
        assert_eq!(
            normalise_disasm("add byte [rax + 0x4532522d], bh", false),
            "add byte [rax + MEM] bh"
        );
    }

    #[test]
    fn test_disasm_x86_str_value() {
        assert_eq!(
            normalise_disasm("lea rdi, str.This_is_a_very_silly_program_", false),
            "lea rdi STR"
        );
        assert_eq!(
            normalise_disasm("str.This_is_a_very_silly_program_ something", false),
            "STR something"
        );
        assert_eq!(
            normalise_disasm("mov eax str.This_is_a_very_silly_program_s", true),
            "mov reg32 STR"
        );
        assert_eq!(
            normalise_disasm("mov eax str.AnotherOne", true),
            "mov reg32 STR"
        )
    }

    #[test]
    fn test_disasm_x86_obj_in_brackets() {
        assert_eq!(
            normalise_disasm("movzx ecx word [obj.DNS::Factory::progressiveId]", true),
            "movzx reg32 word DATA"
        )
    }

    #[test]
    fn test_disasm_x86_stderr_reloc_in_brackets() {
        assert_eq!(
            normalise_disasm("mov reg64 qword [reloc.stderr]", true),
            "mov reg64 qword FUNC"
        )
    }

    // MIPS Disasm Normalisation Tests
    #[test]
    fn test_disasm_mips_cpp_func_call() {
        assert_eq!(normalise_disasm("jal method std::__cxx11::_List_base<FingerTest const*, std::allocator<FingerTest const*> >::~_List_base()", false),
                   "jal FUNC");
        assert_eq!(normalise_disasm("jal method std::__cxx11::_List_base<data_file_record  std::allocator<data_file_record> >::_M_inc_size(unsigned int)", false),
                   "jal FUNC");
        assert_eq!(normalise_disasm("jal method std::reverse_iterator<__gnu_cxx::__normal_iterator<char const*  std::__cxx11::basic_STRtraits<char>  std::allocator<char> > > > const&)", false),
                   "jal FUNC");
        assert_eq!(
            normalise_disasm("jal method std::__cxx11::basic_STRtraits<char>", false),
            "jal FUNC"
        );
        assert_eq!(normalise_disasm("jal method __gnu_cxx::__normal_iterator<AVal*  std::vector<AVal  std::allocator<AVal> > > std::copy<__gnu_cxx::__normal_iterator<AVal const*  std::vector<AVal  std::allocator<AVal> > >  __gnu_cxx::__normal_iterator<AVal*  std::vector<AVal  std::allocator<AVal> > > >(__gnu_cxx::__normal_iterator<AVal const*  std::vector<AVal  std::allocator<AVal> > >  __gnu_cxx::__normal_iterator<AVal const*  std::vector<AVal  std::allocator<AVal> > >  __gnu_cxx::__normal_iterator<AVal*  std::vector<AVal  std::allocator<AVa", false),
                   "jal FUNC");
    }

    #[test]
    fn test_disasm_mips_imm_offset_sp() {
        assert_eq!(normalise_disasm("sw fp 0x60(sp)", false), "sw fp IMM(sp)");
        assert_eq!(normalise_disasm("sw fp 0x60c(sp)", false), "sw fp IMM(sp)")
    }

    #[test]
    fn test_disasm_mips_func_call() {
        assert_eq!(normalise_disasm("jal fcn.001f79f0", false), "jal FUNC");
        assert_eq!(normalise_disasm("jal sym.safe_zalloc", false), "jal FUNC");
    }

    #[test]
    fn test_disasm_mips_obj_call() {
        assert_eq!(
            normalise_disasm("lw reg32 -obj.__DTOR_END__(gp)", false),
            "lw reg32 DATA"
        );
        assert_eq!(
            normalise_disasm("addiu a2 reg32 obj.__func__.6741", true),
            "addiu reg32 reg32 DATA"
        );
        assert_eq!(
            normalise_disasm("lw reg32 -obj.__dso_handle(gp)", true),
            "lw reg32 DATA"
        );
        assert_eq!(
            normalise_disasm("daddiu a2 a2 obj.__func__.7160", true),
            "daddiu reg32 reg32 DATA"
        );
    }

    // ARM Disasm Normalisation Tests
    #[test]
    fn test_disasm_arm_reg_brackets() {
        assert_eq!(normalise_disasm("ldr x8 [r2]", true), "ldr reg64 [reg32]");
        assert_eq!(normalise_disasm("ldr x2 [x4]", true), "ldr reg64 [reg64]")
    }

    #[test]
    fn test_disasm_arm_reg_no_brackets() {
        assert_eq!(normalise_disasm("ldr x8 r2", true), "ldr reg64 reg32");
        assert_eq!(normalise_disasm("ldr x3 r2", true), "ldr reg64 reg32")
    }

    #[test]
    fn test_disasm_arm_32_bit_reg() {
        assert_eq!(normalise_disasm("ldr w12 w21", true), "ldr reg32 reg32");
        assert_eq!(normalise_disasm("mov x0 x20", true), "mov reg64 reg64");
        assert_eq!(normalise_disasm("mov x0 w20", true), "mov reg64 reg32")
    }

    #[test]
    fn test_disasm_arm_obj_call() {
        assert_eq!(
            normalise_disasm("adrp reg64 obj.completed.8887", true),
            "adrp reg64 DATA"
        )
    }

    #[test]
    fn test_disasm_arm_fp() {
        assert_eq!(
            normalise_disasm("sub sp sp 0x70 stp x29 x30 [sp IMM] add x29 sp 0x60", true),
            "sub sp sp 0x70 stp fp reg64 [sp IMM] add fp sp 0x60"
        )
    }

    // X86 Disasm Normalisation Tests
    #[test]
    fn test_disasm_x86_reg_norm_with_brackets() {
        assert_eq!(
            normalise_disasm("add byte [rax + 0x3d], bh", true),
            "add byte [reg64 + IMM] bh"
        );
        assert_eq!(
            normalise_disasm("add byte [rax + 0x3d], bh", true),
            "add byte [reg64 + IMM] bh"
        );
        assert_eq!(
            normalise_disasm("xmmword [r12 + 0x224]", true),
            "xmmword [reg64 + IMM]"
        )
    }

    #[test]
    fn test_disasm_x86_reg_times_imm() {
        assert_eq!(
            normalise_disasm("mov qword [rax + rcx*8 + 0x643]", true),
            "mov qword [reg64 + reg64*8 + IMM]"
        );
        assert_eq!(
            normalise_disasm("cmp word [rax + rcx*2]", true),
            "cmp word [reg64 + reg64*2]"
        )
    }

    #[test]
    fn test_disasm_fix_multi_byte_nop() {
        assert_eq!(normalise_disasm("nop word cs:[rax + rax]", true), "nop");
        assert_eq!(normalise_disasm("nop dword [rax + rax]", true), "nop")
    }
}
/*

"0x30,rbp,-,[8],rax,=",
    "0x8,rbp,-,[8],rcx,=",
    "0x74,rcx,+,[4],rdx,=",
    "edx,rcx,=",
    "rcx,rax,-=,rcx,0x8000000000000000,-,!,63,$o,^,of,:=,63,$s,sf,:=,$z,zf,:=,$p,pf,:=,64,$b,cf,:=,3,$b,af,:=",
    "cf,zf,|,!,sil,=",
    "sil,rdx,=",
    "edx,rcx,=",
    "0x70d388,rcx,8,*,+,[8],rcx,=",
    "rax,0x58,rbp,-,=[8]",
    "rcx,rip,=",
 */
