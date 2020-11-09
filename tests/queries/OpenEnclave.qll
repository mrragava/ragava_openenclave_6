/**
 * Provides classes representing ECalls and their parameters.
 */

import cpp
import Dereferences

class ECallArg extends Type {
  ECallArg() { this.getName().matches("oe_call_enclave_function_args_t") }
}

class ECallArgPointerType extends PointerType {
  ECallArgPointerType() { this.getBaseType() instanceof ECallArg }

  override string getAPrimaryQlClass() { result = "ECallArgPointerType" }
}

class OCallArg extends Type {
  OCallArg() { this.getName().matches("oe_call_host_function_args_t") }
}

class OCallArgPointerType extends PointerType {
  OCallArgPointerType() { this.getBaseType() instanceof OCallArg }

  override string getAPrimaryQlClass() { result = "OCallArgPointerType" }
}

class Ecall_Input_Field extends Field {
  Ecall_Input_Field() { this.hasName("input_buffer") }
}

class OE_call_enclave_function_args_t extends Struct {
  OE_call_enclave_function_args_t() {
    this.(Struct).getName().matches("_oe_call_enclave_function_args")
  }

  Field get_function_id() { result = getCanonicalMember(0) }

  Field get_input_buffer() { result = getCanonicalMember(1) }

  Field get_input_buffer_size() { result = getCanonicalMember(2) }

  Field get_output_buffer() { result = getCanonicalMember(3) }

  Field get_output_buffer_size() { result = getCanonicalMember(4) }

  Field get_output_bytes_written() { result = getCanonicalMember(5) }

  Field get_result() { result = getCanonicalMember(6) }
}

class ECallFunction extends Function {
  ECallFunction() { exists(string name | name = getName() | name = "__oe_handle_main") }
}

abstract class UntrustedParameter extends Parameter { }

class ECallParameter extends UntrustedParameter {
  ECallParameter() { this = any(ECallFunction ecall).getAParameter() }
}

class ECallInputParameter extends Parameter {
  ECallInputParameter() { this = any(ECallFunction ecall).getParameter(1) }
}
