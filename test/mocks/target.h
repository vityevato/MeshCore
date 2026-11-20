#pragma once

// Minimal target mock for native tests. CommonRadioPrefs.cpp only touches the
// radio driver through its CLI setters; serialization tests never call them.
struct NativeRadioDriver {
  bool setRxBoostedGainMode(bool) { return true; }
  void setTxPower(int) { }
};

inline NativeRadioDriver radio_driver;
