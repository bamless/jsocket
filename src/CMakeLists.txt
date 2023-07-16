add_library(jsocket SHARED socket.c)
target_link_libraries(jsocket PUBLIC jstar::jstar)
set_target_properties(jsocket PROPERTIES OUTPUT_NAME "socket")
target_compile_options(jsocket
    PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W3>
        $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra>
        $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra>
)

if(LTO)
    set_target_properties(jsocket PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif(LTO)

include(GNUInstallDirs)
install(TARGETS jsocket LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/jstar)
install(FILES socket.jsr DESTINATION ${CMAKE_INSTALL_LIBDIR}/jstar)
