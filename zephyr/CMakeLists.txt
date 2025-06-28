# CMakeLists.txt for liboprf integration with Zephyr

if(CONFIG_LIBOPRF)
  # Create a Zephyr library for the platform-specific adaptations
  zephyr_library_named(oprf_zephyr)
  
  # Define source directories
  set(LIBOPRF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
  set(LIBOPRF_SRC_DIR ${LIBOPRF_DIR}/src)
  
  # Build liboprf directly (no external build process)
  #zephyr_library_named(oprf)
  
  # Add necessary includes
  zephyr_include_directories(
     ${LIBOPRF_DIR}/src
     ${LIBOPRF_DIR}/src/noise_xk/include
     ${LIBOPRF_DIR}/src/noise_xk/include/karmel
     ${LIBOPRF_DIR}/src/noise_xk/include/karmel/minimal
  )
  
  # Make the includes available to applications
  zephyr_library_include_directories(
     ${LIBOPRF_DIR}/src
     ${LIBOPRF_DIR}/src/noise_xk/include
     ${LIBOPRF_DIR}/src/noise_xk/include/karmel
     ${LIBOPRF_DIR}/src/noise_xk/include/karmel/minimal
  )
  
  FILE(GLOB lib_sources 
     ${LIBOPRF_SRC_DIR}/*.c 
     ${LIBOPRF_SRC_DIR}/noise_xk/src/*.c)
  # Add all necessary source files
  zephyr_library_sources(${lib_sources})
endif()
