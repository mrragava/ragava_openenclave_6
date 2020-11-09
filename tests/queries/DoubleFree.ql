/**
 * @name Double-Free Vulnerability
 * @description Potential Double-Free Vulnerability
 * @kind problem
 * @id acc/doublefree
 * @problem.severity warning
 * @tags security
 * @precision low
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards
import UseAfterFree
import Exclusions

from EffectiveFreeCall freeCall, VariableAccess use, DataFlow::Node source
where
  not use.getTarget() instanceof StackVariable and
  (useAfterFree(source, freeCall, _, use) or useAfterFree(source, freeCall, use, _)) and
  use = any(EffectiveFreeCall freeCall2).getAFreedArgument() and
  oe_exclude_depends(use.getFile())
select use, "Memory released here but not set to NULL, Potential Double-Free Vulnerability"
