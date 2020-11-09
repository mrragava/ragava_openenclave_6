/**
 * @name Missing boundary check when accessing untrusted memory.
 * @description When host pointers are passed as arguments to ECall, There has to a check 
 *              to validate if the memory region is outside the enclave memory boundary.
 * @kind problem
 * @id acc/ecall-args-isoutsideenclave
 * @problem.severity warning
 * @tags security
 * @precision medium
 */

import cpp
import semmle.code.cpp.Type
import semmle.code.cpp.dataflow.TaintTracking
import OpenEnclave

class UntrustedData extends Expr {
  UntrustedData() { this instanceof Expr }

  predicate comesFrom(ECallInputParameter p) {
    parameterUsePair(p, this)
    or
    exists(UntrustedData userData |
      // A use of a variable where the def was untrusted data
      definitionUsePair(_, userData, this)
      or
      // Used in a function call
      exists(FunctionCall fc, int pos | fc.getArgument(pos) = userData |
        parameterUsePair(fc.getTarget().getParameter(pos), this)
      )
    |
      userData.comesFrom(p)
    )
  }
}

class IsOutsideEnclaveFunction extends Function {
  IsOutsideEnclaveFunction() { this.getName() = "oe_is_outside_enclave" }
}

class IsOutsideEnclaveFunctionCall extends FunctionCall {
  IsOutsideEnclaveFunctionCall() { this.getTarget() instanceof IsOutsideEnclaveFunction }
}

class TestBarrierGuard extends DataFlow2::BarrierGuard {
  TestBarrierGuard() { this instanceof IsOutsideEnclaveFunctionCall }

  override predicate checks(Expr checked, boolean isTrue) {
    checked = this.(IsOutsideEnclaveFunctionCall).getArgument(0) and
    isTrue = true
  }
}

class EnclaveBarrierFlow extends DataFlow::Configuration {
  EnclaveBarrierFlow() { this = "EnclaveBarrierFlow" }

  override predicate isSource(DataFlow::Node source) {
    not exists(IsOutsideEnclaveFunctionCall fc | fc.getArgument(0) = source.asExpr())
    // any()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(AssignExpr assExp |
      assExp.getRValue() = sink.asExpr() and
      assExp.getLValue().getType() instanceof PointerType
    )
  }

  override predicate isBarrierGuard(DataFlow::BarrierGuard bg) { bg instanceof TestBarrierGuard }
}

from
  UntrustedData data, ECallInputParameter p, EnclaveBarrierFlow config
where
  data.comesFrom(p) and
  config.hasFlow(DataFlow::exprNode(data), DataFlow::exprNode(data))
select data, "Missing boundary check when accessing untrusted memory."