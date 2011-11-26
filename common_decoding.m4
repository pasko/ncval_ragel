  action rel8_operand {
    operand0 = JMP_TO;
    base = REG_RIP;
    index = REG_NONE;
    scale = 0;
    disp_type = DISP8;
    disp = p;
  }
  define(｢rel8_operand｣, ｢@rel8｢_｣operand｣)
  action rel16_operand {
    operand0 = JMP_TO;
    base = REG_RIP;
    index = REG_NONE;
    scale = 0;
    disp_type = DISP16;
    disp = p - 1;
  }
  define(｢rel16_operand｣, ｢@rel16｢_｣operand｣)
  action rel32_operand {
    operand0 = JMP_TO;
    base = REG_RIP;
    index = REG_NONE;
    scale = 0;
    disp_type = DISP32;
    disp = p - 3;
  }
  define(｢rel32_operand｣, ｢@rel32｢_｣operand｣)
  action branch_not_taken {
    branch_taken = TRUE;
  }
  define(｢branch_not_taken｣, ｢@branch｢_｣not｢_｣taken｣)
  action branch_taken {
    branch_taken = TRUE;
  }
  define(｢branch_taken｣, ｢@branch｢_｣taken｣)
  action data16_prefix {
    data16_prefix = TRUE;
  }
  define(｢data16_prefix｣, ｢@data16｢_｣prefix｣)
  action lock_prefix {
    lock_prefix = TRUE;
  }
  define(｢lock_prefix｣, ｢@lock｢_｣prefix｣)
  action rep_prefix {
    repz_prefix = TRUE;
  }
  define(｢rep_prefix｣, ｢@rep｢_｣prefix｣)
  action repz_prefix {
    repz_prefix = TRUE;
  }
  define(｢repz_prefix｣, ｢@repz｢_｣prefix｣)
  action repnz_prefix {
    repnz_prefix = TRUE;
  }
  define(｢repnz_prefix｣, ｢@repnz｢_｣prefix｣)
  action disp8_operand {
    disp_type = DISP8;
    disp = p;
  }
  define(｢disp8_operand｣, ｢@disp8｢_｣operand｣)
  action disp32_operand {
    disp_type = DISP32;
    disp = p - 3;
  }
  define(｢disp32_operand｣, ｢@disp32｢_｣operand｣)
  action disp64_operand {
    disp_type = DISP64;
    disp = p - 7;
  }
  define(｢disp64_operand｣, ｢@disp64｢_｣operand｣)
  action imm8_operand {
    imm_operand = IMM8;
    imm = p;
  }
  define(｢imm8_operand｣, ｢@imm8｢_｣operand｣)
  action imm8_second_operand {
    imm2_operand = IMM8;
    imm2 = p;
  }
  define(｢imm8_second_operand｣, ｢@imm8｢_｣second｢_｣operand｣)
  action imm16_operand {
    imm_operand = IMM16;
    imm = p - 1;
  }
  define(｢imm16_operand｣, ｢@imm16｢_｣operand｣)
  action imm16_second_operand {
    imm2_operand = IMM16;
    imm2 = p - 1;
  }
  define(｢imm16_second_operand｣, ｢@imm16｢_｣second｢_｣operand｣)
  action imm32_operand {
    imm_operand = IMM32;
    imm = p - 3;
  }
  define(｢imm32_operand｣, ｢@imm32｢_｣operand｣)
  action imm32_second_operand {
    imm2_operand = IMM32;
    imm2 = p - 3;
  }
  define(｢imm32_second_operand｣, ｢@imm32｢_｣second｢_｣operand｣)
  action imm64_operand {
    imm_operand = IMM64;
    imm = p - 7;
  }
  define(｢imm64_operand｣, ｢@imm64｢_｣operand｣)
  action imm64_second_operand {
    imm2_operand = IMM64;
    imm2 = p - 7;
  }
  define(｢imm64_second_operand｣, ｢@imm64｢_｣second｢_｣operand｣)
  action modrm_only_base {
    disp_type = DISPNONE;
    index = REG_NONE;
    base = ((*p) & 0x07) | ((rex_prefix & REX_B) << 3);
  }
  define(｢modrm_only_base｣, ｢@modrm｢_｣only｢_｣base｣)
  action modrm_base_disp {
    index = REG_NONE;
    base = ((*p) & 0x07) | ((rex_prefix & REX_B) << 3);
  }
  define(｢modrm_base_disp｣, ｢@modrm｢_｣base｢_｣disp｣)
  action modrm_rip {
    index = REG_NONE;
    base = REG_RIP;
  }
  define(｢modrm_rip｣, ｢@modrm｢_｣rip｣)
  action modrm_pure_disp {
    base = REG_NONE;
    index = REG_NONE;
  }
  define(｢modrm_pure_disp｣, ｢@modrm｢_｣pure｢_｣disp｣)
  action modrm_pure_index {
    disp_type = DISPNONE;
    base = REG_NONE;
    index = index_registers[(((*p) & 0x38) >> 3) | ((rex_prefix & REX_X) << 2)];
    scale = ((*p) & 0xc0) >> 6;
  }
  define(｢modrm_pure_index｣, ｢@modrm｢_｣pure｢_｣index｣)
  action modrm_parse_sib {
    disp_type = DISPNONE;
    base = ((*p) & 0x7) | ((rex_prefix & REX_B) << 3);
    index = index_registers[(((*p) & 0x38) >> 3) | ((rex_prefix & REX_X) << 2)];
    scale = ((*p) & 0xc0) >> 6;
  }
  define(｢modrm_parse_sib｣, ｢@modrm｢_｣parse｢_｣sib｣)
  action check_access {
  }
  define(｢check_access｣, ｢@check｢_｣access｣)

  action begin_opcode {
    begin_opcode = p;
  }
  action end_opcode {
    end_opcode = p;
  }
  define(｢begin_opcode｣, ｢$1 >begin｢_｣opcode｣)
  define(｢end_opcode｣, ｢@end｢_｣opcode｣)
  define(｢operand_size｣,
    ｢action operand0_$1 {
      operand0_size = OperandSize$2;
     }
     define(｢operand0_$1｣, ｢@operand0｢_｣$1｣)
     action operand1_$1 {
      operand1_size = OperandSize$2;
     }
     define(｢operand1_$1｣, ｢@operand1｢_｣$1｣)
     action operand2_$1 {
      operand2_size = OperandSize$2;
     }
     define(｢operand2_$1｣, ｢@operand2｢_｣$1｣)
     action operand3_$1 {
      operand3_size = OperandSize$2;
     }
     define(｢operand3_$1｣, ｢@operand3｢_｣$1｣)
     action operand4_$1 {
      operand4_size = OperandSize$2;
     }
     define(｢operand4_$1｣, ｢@operand4｢_｣$1｣)
     ifdef(｢OperandSizeList｣,
       ｢append(｢OperandSizeList｣,｢, OperandSize$2｣)｣,
       ｢define(｢OperandSizeList｣,｢OperandSize$2｣)｣)｣)
  operand_size(8bit, 8bit)
  operand_size(16bit, 16bit)
  operand_size(32bit, 32bit)
  operand_size(64bit, 64bit)
  operand_size(x87, X87)
  operand_size(mm, MM)
  operand_size(xmm, XMM)
  operand_size(ymm, YMM)
  action operands_count_is_0 {
    operands_count = 0;
  }
  define(｢operands_count_is_0｣, ｢@operands｢_｣count｢_｣is｢_｣0｣)
  action operands_count_is_1 {
    operands_count = 1;
  }
  define(｢operands_count_is_1｣, ｢@operands｢_｣count｢_｣is｢_｣1｣)
  action operands_count_is_2 {
    operands_count = 2;
  }
  define(｢operands_count_is_2｣, ｢@operands｢_｣count｢_｣is｢_｣2｣)
  action operands_count_is_3 {
    operands_count = 3;
  }
  define(｢operands_count_is_3｣, ｢@operands｢_｣count｢_｣is｢_｣3｣)
  action operands_count_is_4 {
    operands_count = 4;
  }
  define(｢operands_count_is_4｣, ｢@operands｢_｣count｢_｣is｢_｣4｣)
  action operands_count_is_5 {
    operands_count = 5;
  }
  define(｢operands_count_is_5｣, ｢@operands｢_｣count｢_｣is｢_｣5｣)
  action operand0_absolute_disp {
    operand0 = REG_RM;
    base = REG_NONE;
    index = REG_RIZ;
    scale = 0;
  }
  define(｢operand0_absolute_disp｣, ｢@operand0｢_｣absolute｢_｣disp｣)
  action operand0_accumulator {
    operand0 = REG_RAX;
  }
  define(｢operand0_accumulator｣, ｢@operand0｢_｣accumulator｣)
  action operand0_ds_rbx {
    operand0 = REG_DS_RBX;
  }
  define(｢operand0_ds_rbx｣, ｢@operand0｢_｣ds｢_｣rbx｣)
  action operand0_ds_rsi {
    operand0 = REG_DS_RSI;
  }
  define(｢operand0_ds_rsi｣, ｢@operand0｢_｣ds｢_｣rsi｣)
  action operand0_es_rdi {
    operand0 = REG_ES_RDI;
  }
  define(｢operand0_es_rdi｣, ｢@operand0｢_｣es｢_｣rdi｣)
  action operand0_from_opcode {
    operand0 = ((*p) & 0x7) | ((rex_prefix & REX_B) << 3);
  }
  define(｢operand0_from_opcode｣, ｢@operand0｢_｣from｢_｣opcode｣)
  action operand0_from_modrm_reg {
    operand0 = (((*p) & 0x38) >> 3) | ((rex_prefix & REX_R) << 1);
  }
  define(｢operand0_from_modrm_reg｣, ｢@operand0｢_｣from｢_｣modrm｢_｣reg｣)
  action operand0_immediate {
    operand0 = REG_IMM;
  }
  define(｢operand0_immediate｣, ｢@operand0｢_｣immediate｣)
  action operand0_port_dx {
    operand0 = REG_PORT_DX;
  }
  define(｢operand0_port_dx｣, ｢@operand0｢_｣port｢_｣dx｣)
  action operand0_rm {
    operand0 = REG_RM;
  }
  define(｢operand0_rm｣, ｢@operand0｢_｣rm｣)
  action operand1_absolute_disp {
    operand1 = REG_RM;
    base = REG_NONE;
    index = REG_RIZ;
    scale = 0;
  }
  define(｢operand1_absolute_disp｣, ｢@operand1｢_｣absolute｢_｣disp｣)
  action operand1_accumulator {
    operand1 = REG_RAX;
  }
  define(｢operand1_accumulator｣, ｢@operand1｢_｣accumulator｣)
  action operand1_ds_rsi {
    operand1 = REG_DS_RSI;
  }
  define(｢operand1_ds_rsi｣, ｢@operand1｢_｣ds｢_｣rsi｣)
  action operand1_es_rdi {
    operand1 = REG_ES_RDI;
  }
  define(｢operand1_es_rdi｣, ｢@operand1｢_｣es｢_｣rdi｣)
  action operand1_from_modrm_reg {
    operand1 = (((*p) & 0x38) >> 3) | ((rex_prefix & REX_R) << 1);
  }
  define(｢operand1_from_modrm_reg｣, ｢@operand1｢_｣from｢_｣modrm｢_｣reg｣)
  action operand0_from_modrm_rm {
    operand0 = ((*p) & 0x07) | ((rex_prefix & REX_B) << 3);
  }
  define(｢operand0_from_modrm_rm｣, ｢@operand0｢_｣from｢_｣modrm｢_｣rm｣)
  action operand1_from_modrm_rm {
    operand1 = ((*p) & 0x07) | ((rex_prefix & REX_B) << 3);
  }
  define(｢operand1_from_modrm_rm｣, ｢@operand1｢_｣from｢_｣modrm｢_｣rm｣)
  action operand1_immediate {
    operand1 = REG_IMM;
  }
  define(｢operand1_immediate｣, ｢@operand1｢_｣immediate｣)
  action operand1_port_dx {
    operand1 = REG_PORT_DX;
  }
  define(｢operand1_port_dx｣, ｢@operand1｢_｣port｢_｣dx｣)
  action operand1_rm {
    operand1 = REG_RM;
  }
  define(｢operand1_rm｣, ｢@operand1｢_｣rm｣)
  action operand1_second_immediate {
    operand1 = REG_IMM2;
  }
  define(｢operand1_second_immediate｣, ｢@operand1｢_｣second｢_｣immediate｣)
  action operand2_immediate {
    operand2 = REG_IMM;
  }
  define(｢operand2_immediate｣, ｢@operand2｢_｣immediate｣)
