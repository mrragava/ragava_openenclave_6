/**
 * @name Uninitialized argument used in OCall.
 * @description Passing uninitialized argument to an OCall could lead to information disclosure.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id acc/ocall-args-uninitialized
 * @tags security
 */

import cpp
import semmle.code.cpp.Type
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.models.implementations.Strcpy
import Exclusions

class OCallFunction extends Function {
  OCallFunction() { this.getName().matches("%_ocall") }
}

class OCallFunctionCall extends FunctionCall {
  OCallFunctionCall() { this.getTarget().getName().matches("%_ocall") }
}

from LocalVariable v, VariableAccess va, OCallFunctionCall ofnCall
where
  ofnCall.getNumberOfArguments() > 0 and
  ofnCall.getAnArgumentSubExpr(_) = va and
  v = va.getTarget() and
  oe_exclude_depends(ofnCall.getFile()) and
  not exists(v.getInitializer()) and
  not exists(v.getAnAssignment()) and
  not v.getAnAccess() =
    any(Call c | c.getTarget().getName().matches("%mem%")).getAnArgumentSubExpr(0) and
  DataFlow::localFlowStep(DataFlow::exprNode(v.getAnAccess()), _)
select va, "Uninitialized argument passed to OCall"
