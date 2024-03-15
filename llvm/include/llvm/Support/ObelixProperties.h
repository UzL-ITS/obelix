

#ifndef LLVM_OBELIXPROPERTIES_H
#define LLVM_OBELIXPROPERTIES_H

#include "llvm/ADT/BitmaskEnum.h"
#include "llvm/ADT/Sequence.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm {
class ObelixProperties {

public:

  /// The different states of an annotated function.
  enum State {
    /// Marked as needing instrumentation, but not yet visited by pass.
    Marked = 0,

    /// Original version of a function that was marked as needing instrumentation.
    Original = 1,

    /// Copied version of a function that was marked as needing instrumentation.
    Copy = 2,

    /// Obelix-protected function residing in another compilation unit or library.
    /// Necessary to correctly transform calls to instrumented functions.
    Extern = 3,

    /// Automatically copied version of a function that was called from another
    /// instrumented function.
    AutoCopy = 4
  };

private:

  uint32_t Data = 0;

  static constexpr uint32_t StateBits = 3;
  static constexpr uint32_t StateMask = (1 << StateBits) - 1;

  ObelixProperties(uint32_t Data) : Data(Data) {}

  void setState(State state) {
    Data &= ~StateMask;
    Data |= static_cast<uint32_t>(state);
  }

  friend raw_ostream &operator<<(raw_ostream &OS, ObelixProperties &OP);

public:

  /// Creates an ObelixProperties annotation with the given state.
  explicit ObelixProperties(State State) {
    setState(State);
  }

  /// Create an ObelixProperties object from an encoded integer value (used by the IR
  /// attribute).
  static ObelixProperties createFromIntValue(uint32_t Data) {
    return ObelixProperties(Data);
  }

  /// Convert this object into an encoded integer value (used by the IR
  /// attribute).
  uint32_t toIntValue() const {
    return Data;
  }

  /// Returns the state.
  State getState() const {
    return static_cast<State>(Data & StateMask);
  }

  /// Get a copy of this object with modified state.
  ObelixProperties getWithState(State NewState) const {
    ObelixProperties OP = *this;
    OP.setState(NewState);
    return OP;
  }

  static const char *getStateString(State State) {
    switch(State) {
    case State::Marked:
      return "marked";
    case State::Original:
      return "original";
    case State::Copy:
      return "copy";
    case State::Extern:
      return "extern";
    case State::AutoCopy:
      return "autocopy";
    }
    llvm_unreachable("Invalid ObelixProperties State");
  }

};

/// Debug print ObelixProperties.
raw_ostream &operator<<(raw_ostream &OS, const ObelixProperties &OP);

} // namespace llvm

#endif // LLVM_OBELIXPROPERTIES_H
