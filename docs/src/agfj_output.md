# agfj JSON

```json

        {
            "blocks": [
                {
                    "fail": 4467,
                    "jump": 4486,
                    "offset": 4425,
                    "ops": [
                        {
                            "bytes": "f30f1efa",
                            "disasm": "endbr64",
                            "esil": "",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4582,
                            "flags": [
                                "main",
                                "sym.main"
                            ],
                            "offset": 4425,
                            "opcode": "endbr64",
                            "refptr": 0,
                            "reloc": false,
                            "size": 4,
                            "type": "null",
                            "type2_num": 0,
                            "type_num": 0,
                            "xrefs": [
                                {
                                    "addr": 4225,
                                    "perm": "r--",
                                    "type": "DATA"
                                }
                            ]
                        },
                        {
                            "bytes": "55",
                            "disasm": "push rbp",
                            "esil": "rbp,8,rsp,-,=[8],8,rsp,-=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4585,
                            "offset": 4429,
                            "opcode": "push rbp",
                            "refptr": 0,
                            "reloc": false,
                            "size": 1,
                            "type": "rpush",
                            "type2_num": 0,
                            "type_num": 268435468
                        },
                        {
                            "bytes": "4889e5",
                            "disasm": "mov rbp, rsp",
                            "esil": "rsp,rbp,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4583,
                            "offset": 4430,
                            "opcode": "mov rbp, rsp",
                            "refptr": 0,
                            "reloc": false,
                            "size": 3,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9
                        },
                        {
                            "bytes": "4883ec10",
                            "disasm": "sub rsp, 0x10",
                            "esil": "16,rsp,-=,16,0x8000000000000000,-,!,63,$o,^,of,:=,63,$s,sf,:=,$z,zf,:=,$p,pf,:=,64,$b,cf,:=,3,$b,af,:=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4582,
                            "offset": 4433,
                            "opcode": "sub rsp, 0x10",
                            "refptr": 0,
                            "reloc": false,
                            "size": 4,
                            "type": "sub",
                            "type2_num": 0,
                            "type_num": 18,
                            "val": 16
                        },
                        {
                            "bytes": "488d3da80e0000",
                            "disasm": "lea rdi, str.This_is_a_very_silly_program_",
                            "esil": "0xea8,rip,+,rdi,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4579,
                            "offset": 4437,
                            "opcode": "lea rdi, [rip + 0xea8]",
                            "ptr": 8196,
                            "refptr": 8,
                            "refs": [
                                {
                                    "addr": 8196,
                                    "perm": "r--",
                                    "type": "DATA"
                                }
                            ],
                            "reloc": false,
                            "size": 7,
                            "type": "lea",
                            "type2_num": 0,
                            "type_num": 33
                        },
                        {
                            "bytes": "b800000000",
                            "disasm": "mov eax, 0",
                            "esil": "0,rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "offset": 4444,
                            "opcode": "mov eax, 0",
                            "refptr": 0,
                            "reloc": false,
                            "size": 5,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "val": 0
                        },
                        {
                            "bytes": "e8eafeffff",
                            "disasm": "call sym.imp.printf",
                            "esil": "4176,rip,8,rsp,-=,rsp,=[8],rip,=",
                            "fail": 4454,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "jump": 4176,
                            "offset": 4449,
                            "opcode": "call 0x1050",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4176,
                                    "perm": "--x",
                                    "type": "CALL"
                                }
                            ],
                            "reloc": false,
                            "size": 5,
                            "type": "call",
                            "type2_num": 0,
                            "type_num": 3
                        },
                        {
                            "bytes": "c745f800000000",
                            "disasm": "mov dword [rbp - 8], 0",
                            "esil": "0,0x8,rbp,-,=[4]",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4579,
                            "offset": 4454,
                            "opcode": "mov dword [rbp - 8], 0",
                            "refptr": 4,
                            "reloc": false,
                            "size": 7,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 268435465,
                            "val": 0
                        },
                        {
                            "bytes": "837df801",
                            "disasm": "cmp dword [rbp - 8], 1",
                            "esil": "1,0x8,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,31,$s,sf,:=,1,0x80000000,-,!,31,$o,^,of,:=,3,$b,af,:=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4582,
                            "offset": 4461,
                            "opcode": "cmp dword [rbp - 8], 1",
                            "refptr": 4,
                            "reloc": false,
                            "size": 4,
                            "type": "cmp",
                            "type2_num": 0,
                            "type_num": 268435471,
                            "val": 1
                        },
                        {
                            "bytes": "7413",
                            "disasm": "je 0x1186",
                            "esil": "zf,?{,4486,rip,=,}",
                            "fail": 4467,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4584,
                            "jump": 4486,
                            "offset": 4465,
                            "opcode": "je 0x1186",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4486,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ],
                            "reloc": false,
                            "size": 2,
                            "type": "cjmp",
                            "type2_num": 0,
                            "type_num": 2147483649
                        }
                    ],
                    "size": 42
                },
                {
                    "jump": 4503,
                    "offset": 4467,
                    "ops": [
                        {
                            "bytes": "488d3da80e0000",
                            "disasm": "lea rdi, str.Not_one_",
                            "esil": "0xea8,rip,+,rdi,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4579,
                            "offset": 4467,
                            "opcode": "lea rdi, [rip + 0xea8]",
                            "ptr": 8226,
                            "refptr": 8,
                            "refs": [
                                {
                                    "addr": 8226,
                                    "perm": "r--",
                                    "type": "DATA"
                                }
                            ],
                            "reloc": false,
                            "size": 7,
                            "type": "lea",
                            "type2_num": 0,
                            "type_num": 33
                        },
                        {
                            "bytes": "b800000000",
                            "disasm": "mov eax, 0",
                            "esil": "0,rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "offset": 4474,
                            "opcode": "mov eax, 0",
                            "refptr": 0,
                            "reloc": false,
                            "size": 5,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "val": 0
                        },
                        {
                            "bytes": "e8ccfeffff",
                            "disasm": "call sym.imp.printf",
                            "esil": "4176,rip,8,rsp,-=,rsp,=[8],rip,=",
                            "fail": 4484,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "jump": 4176,
                            "offset": 4479,
                            "opcode": "call 0x1050",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4176,
                                    "perm": "--x",
                                    "type": "CALL"
                                }
                            ],
                            "reloc": false,
                            "size": 5,
                            "type": "call",
                            "type2_num": 0,
                            "type_num": 3
                        },
                        {
                            "bytes": "eb11",
                            "disasm": "jmp 0x1197",
                            "esil": "0x1197,rip,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4584,
                            "jump": 4503,
                            "offset": 4484,
                            "opcode": "jmp 0x1197",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4503,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ],
                            "reloc": false,
                            "size": 2,
                            "type": "jmp",
                            "type2_num": 0,
                            "type_num": 1
                        }
                    ],
                    "size": 19
                },
                {
                    "jump": 4503,
                    "offset": 4486,
                    "ops": [
                        {
                            "bytes": "488d3d9e0e0000",
                            "disasm": "lea rdi, str.Hello__World_",
                            "esil": "0xe9e,rip,+,rdi,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4579,
                            "offset": 4486,
                            "opcode": "lea rdi, [rip + 0xe9e]",
                            "ptr": 8235,
                            "refptr": 8,
                            "refs": [
                                {
                                    "addr": 8235,
                                    "perm": "r--",
                                    "type": "DATA"
                                }
                            ],
                            "reloc": false,
                            "size": 7,
                            "type": "lea",
                            "type2_num": 0,
                            "type_num": 33,
                            "xrefs": [
                                {
                                    "addr": 4465,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ]
                        },
                        {
                            "bytes": "b800000000",
                            "disasm": "mov eax, 0",
                            "esil": "0,rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "offset": 4493,
                            "opcode": "mov eax, 0",
                            "refptr": 0,
                            "reloc": false,
                            "size": 5,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "val": 0
                        },
                        {
                            "bytes": "e8b9feffff",
                            "disasm": "call sym.imp.printf",
                            "esil": "4176,rip,8,rsp,-=,rsp,=[8],rip,=",
                            "fail": 4503,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "jump": 4176,
                            "offset": 4498,
                            "opcode": "call 0x1050",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4176,
                                    "perm": "--x",
                                    "type": "CALL"
                                }
                            ],
                            "reloc": false,
                            "size": 5,
                            "type": "call",
                            "type2_num": 0,
                            "type_num": 3
                        }
                    ],
                    "size": 17
                },
                {
                    "fail": 4518,
                    "jump": 4537,
                    "offset": 4503,
                    "ops": [
                        {
                            "bytes": "8b45f8",
                            "disasm": "mov eax, dword [rbp - 8]",
                            "esil": "0x8,rbp,-,[4],rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4583,
                            "offset": 4503,
                            "opcode": "mov eax, dword [rbp - 8]",
                            "refptr": 4,
                            "reloc": false,
                            "size": 3,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "xrefs": [
                                {
                                    "addr": 4484,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ]
                        },
                        {
                            "bytes": "83c001",
                            "disasm": "add eax, 1",
                            "esil": "1,eax,+=,31,$o,of,:=,31,$s,sf,:=,$z,zf,:=,31,$c,cf,:=,$p,pf,:=,3,$c,af,:=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4583,
                            "offset": 4506,
                            "opcode": "add eax, 1",
                            "refptr": 0,
                            "reloc": false,
                            "size": 3,
                            "type": "add",
                            "type2_num": 0,
                            "type_num": 17,
                            "val": 1
                        },
                        {
                            "bytes": "8945fc",
                            "disasm": "mov dword [rbp - 4], eax",
                            "esil": "eax,0x4,rbp,-,=[4]",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4583,
                            "offset": 4509,
                            "opcode": "mov dword [rbp - 4], eax",
                            "refptr": 4,
                            "reloc": false,
                            "size": 3,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 268435465
                        },
                        {
                            "bytes": "837dfc00",
                            "disasm": "cmp dword [rbp - 4], 0",
                            "esil": "0,0x4,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,31,$s,sf,:=,0,0x80000000,-,!,31,$o,^,of,:=,3,$b,af,:=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4582,
                            "offset": 4512,
                            "opcode": "cmp dword [rbp - 4], 0",
                            "refptr": 4,
                            "reloc": false,
                            "size": 4,
                            "type": "cmp",
                            "type2_num": 0,
                            "type_num": 268435471,
                            "val": 0
                        },
                        {
                            "bytes": "7413",
                            "disasm": "je 0x11b9",
                            "esil": "zf,?{,4537,rip,=,}",
                            "fail": 4518,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4584,
                            "jump": 4537,
                            "offset": 4516,
                            "opcode": "je 0x11b9",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4537,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ],
                            "reloc": false,
                            "size": 2,
                            "type": "cjmp",
                            "type2_num": 0,
                            "type_num": 2147483649
                        }
                    ],
                    "size": 15
                },
                {
                    "jump": 4579,
                    "offset": 4518,
                    "ops": [
                        {
                            "bytes": "488d3d8c0e0000",
                            "disasm": "lea rdi, str.Not_zero_",
                            "esil": "0xe8c,rip,+,rdi,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4579,
                            "offset": 4518,
                            "opcode": "lea rdi, [rip + 0xe8c]",
                            "ptr": 8249,
                            "refptr": 8,
                            "refs": [
                                {
                                    "addr": 8249,
                                    "perm": "r--",
                                    "type": "DATA"
                                }
                            ],
                            "reloc": false,
                            "size": 7,
                            "type": "lea",
                            "type2_num": 0,
                            "type_num": 33
                        },
                        {
                            "bytes": "b800000000",
                            "disasm": "mov eax, 0",
                            "esil": "0,rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "offset": 4525,
                            "opcode": "mov eax, 0",
                            "refptr": 0,
                            "reloc": false,
                            "size": 5,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "val": 0
                        },
                        {
                            "bytes": "e899feffff",
                            "disasm": "call sym.imp.printf",
                            "esil": "4176,rip,8,rsp,-=,rsp,=[8],rip,=",
                            "fail": 4535,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "jump": 4176,
                            "offset": 4530,
                            "opcode": "call 0x1050",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4176,
                                    "perm": "--x",
                                    "type": "CALL"
                                }
                            ],
                            "reloc": false,
                            "size": 5,
                            "type": "call",
                            "type2_num": 0,
                            "type_num": 3
                        },
                        {
                            "bytes": "eb2a",
                            "disasm": "jmp 0x11e3",
                            "esil": "0x11e3,rip,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4584,
                            "jump": 4579,
                            "offset": 4535,
                            "opcode": "jmp 0x11e3",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4579,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ],
                            "reloc": false,
                            "size": 2,
                            "type": "jmp",
                            "type2_num": 0,
                            "type_num": 1
                        }
                    ],
                    "size": 19
                },
                {
                    "fail": 4543,
                    "jump": 4562,
                    "offset": 4537,
                    "ops": [
                        {
                            "bytes": "837dfc0a",
                            "disasm": "cmp dword [rbp - 4], 0xa",
                            "esil": "10,0x4,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,31,$s,sf,:=,10,0x80000000,-,!,31,$o,^,of,:=,3,$b,af,:=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4582,
                            "offset": 4537,
                            "opcode": "cmp dword [rbp - 4], 0xa",
                            "refptr": 4,
                            "reloc": false,
                            "size": 4,
                            "type": "cmp",
                            "type2_num": 0,
                            "type_num": 268435471,
                            "val": 10,
                            "xrefs": [
                                {
                                    "addr": 4516,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ]
                        },
                        {
                            "bytes": "7513",
                            "disasm": "jne 0x11d2",
                            "esil": "zf,!,?{,4562,rip,=,}",
                            "fail": 4543,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4584,
                            "jump": 4562,
                            "offset": 4541,
                            "opcode": "jne 0x11d2",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4562,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ],
                            "reloc": false,
                            "size": 2,
                            "type": "cjmp",
                            "type2_num": 0,
                            "type_num": 2147483649
                        }
                    ],
                    "size": 6
                },
                {
                    "jump": 4579,
                    "offset": 4543,
                    "ops": [
                        {
                            "bytes": "488d3d7d0e0000",
                            "disasm": "lea rdi, str.Unreachable_silly",
                            "esil": "0xe7d,rip,+,rdi,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4579,
                            "offset": 4543,
                            "opcode": "lea rdi, [rip + 0xe7d]",
                            "ptr": 8259,
                            "refptr": 8,
                            "refs": [
                                {
                                    "addr": 8259,
                                    "perm": "r--",
                                    "type": "DATA"
                                }
                            ],
                            "reloc": false,
                            "size": 7,
                            "type": "lea",
                            "type2_num": 0,
                            "type_num": 33
                        },
                        {
                            "bytes": "b800000000",
                            "disasm": "mov eax, 0",
                            "esil": "0,rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "offset": 4550,
                            "opcode": "mov eax, 0",
                            "refptr": 0,
                            "reloc": false,
                            "size": 5,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "val": 0
                        },
                        {
                            "bytes": "e880feffff",
                            "disasm": "call sym.imp.printf",
                            "esil": "4176,rip,8,rsp,-=,rsp,=[8],rip,=",
                            "fail": 4560,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "jump": 4176,
                            "offset": 4555,
                            "opcode": "call 0x1050",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4176,
                                    "perm": "--x",
                                    "type": "CALL"
                                }
                            ],
                            "reloc": false,
                            "size": 5,
                            "type": "call",
                            "type2_num": 0,
                            "type_num": 3
                        },
                        {
                            "bytes": "eb11",
                            "disasm": "jmp 0x11e3",
                            "esil": "0x11e3,rip,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4584,
                            "jump": 4579,
                            "offset": 4560,
                            "opcode": "jmp 0x11e3",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4579,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ],
                            "reloc": false,
                            "size": 2,
                            "type": "jmp",
                            "type2_num": 0,
                            "type_num": 1
                        }
                    ],
                    "size": 19
                },
                {
                    "jump": 4579,
                    "offset": 4562,
                    "ops": [
                        {
                            "bytes": "488d3d7c0e0000",
                            "disasm": "lea rdi, str.Even_more_unreachable_",
                            "esil": "0xe7c,rip,+,rdi,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4579,
                            "offset": 4562,
                            "opcode": "lea rdi, [rip + 0xe7c]",
                            "ptr": 8277,
                            "refptr": 8,
                            "refs": [
                                {
                                    "addr": 8277,
                                    "perm": "r--",
                                    "type": "DATA"
                                }
                            ],
                            "reloc": false,
                            "size": 7,
                            "type": "lea",
                            "type2_num": 0,
                            "type_num": 33,
                            "xrefs": [
                                {
                                    "addr": 4541,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ]
                        },
                        {
                            "bytes": "b800000000",
                            "disasm": "mov eax, 0",
                            "esil": "0,rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "offset": 4569,
                            "opcode": "mov eax, 0",
                            "refptr": 0,
                            "reloc": false,
                            "size": 5,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "val": 0
                        },
                        {
                            "bytes": "e86dfeffff",
                            "disasm": "call sym.imp.printf",
                            "esil": "4176,rip,8,rsp,-=,rsp,=[8],rip,=",
                            "fail": 4579,
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "jump": 4176,
                            "offset": 4574,
                            "opcode": "call 0x1050",
                            "refptr": 0,
                            "refs": [
                                {
                                    "addr": 4176,
                                    "perm": "--x",
                                    "type": "CALL"
                                }
                            ],
                            "reloc": false,
                            "size": 5,
                            "type": "call",
                            "type2_num": 0,
                            "type_num": 3
                        }
                    ],
                    "size": 17
                },
                {
                    "offset": 4579,
                    "ops": [
                        {
                            "bytes": "b800000000",
                            "disasm": "mov eax, 0",
                            "esil": "0,rax,=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4581,
                            "offset": 4579,
                            "opcode": "mov eax, 0",
                            "refptr": 0,
                            "reloc": false,
                            "size": 5,
                            "type": "mov",
                            "type2_num": 0,
                            "type_num": 9,
                            "val": 0,
                            "xrefs": [
                                {
                                    "addr": 4535,
                                    "perm": "--x",
                                    "type": "CODE"
                                },
                                {
                                    "addr": 4560,
                                    "perm": "--x",
                                    "type": "CODE"
                                }
                            ]
                        },
                        {
                            "bytes": "c9",
                            "disasm": "leave",
                            "esil": "rbp,rsp,=,rsp,[8],rbp,=,8,rsp,+=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4585,
                            "offset": 4584,
                            "opcode": "leave",
                            "refptr": 0,
                            "reloc": false,
                            "size": 1,
                            "type": "pop",
                            "type2_num": 0,
                            "type_num": 14
                        },
                        {
                            "bytes": "c3",
                            "disasm": "ret",
                            "esil": "rsp,[8],rip,=,8,rsp,+=",
                            "family": "cpu",
                            "fcn_addr": 4425,
                            "fcn_last": 4585,
                            "offset": 4585,
                            "opcode": "ret",
                            "refptr": 0,
                            "reloc": false,
                            "size": 1,
                            "type": "ret",
                            "type2_num": 0,
                            "type_num": 5
                        }
                    ],
                    "size": 7
                }
            ],
            "name": "main",
            "nargs": 0,
            "ninstr": 38,
            "nlocals": 2,
            "offset": 4425,
            "size": 161,
            "stack": 24,
            "type": "sym"
        }
    ],
```