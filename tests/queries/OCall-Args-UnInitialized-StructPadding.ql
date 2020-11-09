/**
 * @name Possible information leakage from uninitialized padding bytes.
 * @description Uninitialized structure argument with padding bytes passed to OCall
 * @kind problem
 * @problem.severity warning
 * @tags security
 * @microsoft.severity Important
 * @id acc/ocall-args-uninitialized-structpadding
 */

import cpp
import semmle.code.cpp.padding.Padding
import MemoryAllocation
import Exclusions

/**
 * A type which contains wasted space on one or more architectures.
 */
class WastedSpaceType extends PaddedType {
  WastedSpaceType() {
    // At least some wasted space
    any(Architecture arch).wastedSpace(this.getUnspecifiedType()) > 0
    or
    exists(Field f |
      f.getDeclaringType() = this and f.getType().getUnspecifiedType() instanceof WastedSpaceType
    )
  }
}

/** A buffer that is potentially leaked. */
abstract class LeakedBuffer extends Expr { }

/** An allocation that potentially escapes the enclosing function. */
class EscapingAllocation extends LeakedBuffer {
  EscapingAllocation() {
    this instanceof Allocation and
    (
      this instanceof StackAllocation
      implies
      exists(VariableAccess va | va = this.(StackAllocation).getAllocationVariable().getAnAccess() |
        // Returned directly
        exists(ReturnStmt ret | ret.getExpr() = va)
      )
    )
    or
    (
      this instanceof Malloc
      implies
      exists(VariableAccess va | va = this.(Malloc).getAnArgumentSubExpr(0) |
        // Returned directly
        exists(ReturnStmt ret | ret.getExpr() = va)
      )
    )
  }
}

/** Holds if there exists some padding between the first and second elements. */
predicate hasInitialPadding(PaddedType pt) {
  exists(Field firstField | pt.(Struct).getAMember(0) = firstField |
    // We want to see if the first non-struct field has alignment padding after it
    if firstField.getType().getUnderlyingType() instanceof Struct
    then
      // First field is a struct, consider padding within this struct
      hasInitialPadding(firstField.getType().getUnspecifiedType())
    else
      /*
       * Look at the second field, and see how much waste there is between the first and second
       * fields.
       */

      exists(Field secondField, Architecture arch |
        not exists(pt.getABaseClass()) and
        /*
         * There is padding between the first two fields if the second fields
         * ends at a larger offset than where it would end if it came right
         * after the first field.
         */

        pt.fieldIndex(secondField) = 2 and
        pt.fieldEnd(2, arch) > pt.fieldEnd(1, arch) + pt.fieldSize(secondField, arch)
      )
  )
}

class OCallFunctionCall extends FunctionCall {
  OCallFunctionCall() { this.getTarget().getName().matches("%_ocall") }
}

from Variable v, WastedSpaceType wst, VariableAccess va, OCallFunctionCall ofnCall
where
  ofnCall.getAnArgumentSubExpr(_) = va and
  v = va.getTarget() and
  not exists(v.getInitializer()) and
  hasInitialPadding(wst) and
  // On at least one architecture, there is some wasted space in the form of padding
  v.getType().stripType() = wst and
  // The variable is never the target of a memset/memcpy
  not v.getAnAccess() =
    any(Call c | c.getTarget().getName().matches("%mem%")).getAnArgumentSubExpr(0) and
  // The variable is never freed
  not v.getAnAccess() =
    any(Call c | c.getTarget().getName().matches("%free%")).getAnArgumentSubExpr(0) and
  // Ignore stack variables assigned aggregate literals which zero the allocated memory
  not exists(AggregateLiteral al | v.getAnAssignedValue() = al) and
  oe_exclude_depends(ofnCall.getFile())
select va, "Uninitialized structure argument with padding bytes passed to OCall"
