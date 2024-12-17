package goinstrument

// #cgo LDFLAGS: @GOLLVM_INSTALL_LIBDIR@/libclang_rt.profile.a
// void __llvm_profile_initialize_file(void);
// int __llvm_profile_write_file(void);
// void __llvm_profile_reset_counters(void);
import "C"
import (
  "os"
  "os/signal"
  "strconv"
  "syscall"
  "time"
)

// Default delay in seconds if GOINSTRUMENT_WRITE_DELAY environment variable is not set.
const DefaultDelaySeconds = 5

// Write profile to the path specified with -fprofile-generate=/some/path or
// by setting the LLVM_PROFILE_FILE environment variable.
// Using the profiling runtime is documented at the following page:
// https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#using-the-profiling-runtime-without-static-initializers
// We write the collected profile using the profiling runtime through CGO.
func ProfileWriteFile() {
  err := C.__llvm_profile_write_file()
  if err != 0 {
    println("__llvm_profile_write_file failed: error " + strconv.Itoa(int(err)))
  }
}

// Helper for verbose dump.
func dumpSignal(sig os.Signal) {
  switch sig {
  case syscall.SIGINT:
    println("goinstrument.ProfileWriteFile: SIGNINT")
  case syscall.SIGTERM:
    println("goinstrument.ProfileWriteFile: SIGTERM")
  default:
    println("goinstrument.ProfileWriteFile: signal")
  }
}

// Periodic profile write with custom duration.
// May be used with environment variable GOINSTRUMENT_CUSTOM=1.
func PeriodicWrite(delay time.Duration, signals chan os.Signal, verbose bool) {
  ticker := time.NewTicker(delay)
  if signals == nil {
    signals = make(chan os.Signal, 1)
  }
  for {
    select {
    case <-ticker.C:
      if verbose {
        println("goinstrument.ProfileWriteFile: periodic")
      }
      ProfileWriteFile()
    case sig := <-signals:
      if verbose {
        dumpSignal(sig)
      }
      ProfileWriteFile()
      ticker.Stop()
      return
    }
  }
  ticker.Stop()
}

func init() {

  C.__llvm_profile_initialize_file()

  go func() {
    if os.Getenv("GOINSTRUMENT_CUSTOM") != "" {
      // Don't start PeriodicWrite, leave that to the client.
      return
    }

    // Write profile every delaySeconds
    var delaySeconds int
    var err error
    delayString := os.Getenv("GOINSTRUMENT_WRITE_DELAY")
    delaySeconds, err = strconv.Atoi(delayString)
    if err != nil {
      delaySeconds = DefaultDelaySeconds
    }
    delay := time.Duration(delaySeconds) * time.Second

    signals := make(chan os.Signal, 1)
    if os.Getenv("GOINSTRUMENT_SIGNAL") != "" {
      signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
    }

    verbose := false
    if os.Getenv("GOINSTRUMENT_VERBOSE") != "" {
      verbose = true
    }

    PeriodicWrite(delay, signals, verbose)
  }()
}
