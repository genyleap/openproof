#pragma once

// Deliberately included from the global module fragment of http.cpp.
// GCC 16 only permits preprocessor-included declarations in that fragment.
// Keep the Asio TLS storage instantiation anchored in the non-module
// asio_thread_context.cpp translation unit, avoiding module-owned linkage.
// These incomplete declarations must be preprocessor-included in a C++26
// global module fragment, not written as module-fragment source text.
namespace boost::asio::detail {
class thread_context;
class thread_info_base;
}

extern template boost::asio::detail::tss_ptr<
    boost::asio::detail::call_stack<
        boost::asio::detail::thread_context,
        boost::asio::detail::thread_info_base>::context>
boost::asio::detail::call_stack<
    boost::asio::detail::thread_context,
    boost::asio::detail::thread_info_base>::top_;
