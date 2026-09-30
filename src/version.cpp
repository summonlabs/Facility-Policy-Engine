#include "fpe/version.hpp"

#include <string>

namespace fpe {

std::string_view engine_version() {
  static const std::string kVersion =
      std::to_string(kVersionMajor) + "." + std::to_string(kVersionMinor) + "." + std::to_string(kVersionPatch);
  return kVersion;
}

}  // namespace fpe
