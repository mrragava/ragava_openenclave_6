/**
 * @name TOCTOU in ECall Aruguments
 * @description Potential time-of-check and time-of-use vulnerablility in the usage of ECall argiment pointer.
 * @kind problem
 * @id acc/ecall-args-toctou
 * @problem.severity error
 * @tags security
 * @precision medium
 */

import cpp
import semmle.code.cpp.Type
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

from
  UntrustedData data, ECallInputParameter p, AssignExpr assExp, VariableAccess va, StackVariable v,
  Expr expr, FieldAccess fa
where
  data.comesFrom(p) and
  assExp.getRValue() = data and
  va = assExp.getLValue() and
  v = va.getTarget() and
  useUsePair(v, _, expr) and
  expr.getEnclosingElement() = fa and
  fa.getTarget().getUnderlyingType() instanceof PointerType
select fa, "Host pointer is used directly, Potential TOCTOU vulnerablity"
