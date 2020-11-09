import cpp

abstract class Allocation extends Expr { }

class StackAllocation extends Allocation {
  StackAllocation() {
    exists(StackVariable var | var.getType().getUnspecifiedType() instanceof Struct |
      var.getInitializer().getExpr() = this
    )
  }

  StackVariable getAllocationVariable() { result.getInitializer().getExpr() = this }
}

abstract class HeapAllocation extends Allocation, FunctionCall {
  abstract Expr getAllocatedSize();

  override string toString() { result = FunctionCall.super.toString() }
}

class Malloc extends HeapAllocation {
  Malloc() { this.getTarget().getName().matches("%malloc%") }

  override Expr getAllocatedSize() { result = this.getArgument(0) }
}
