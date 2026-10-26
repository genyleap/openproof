// GCC C++26 module interoperability bridge for Boost.Asio 1.88.
// Keep the Asio thread-context template instantiation in an ordinary C++
// translation unit so GCC emits its internal TSS storage as COMDAT, not as a
// conflicting strong definition from a named module implementation unit.
#include <boost/asio/detail/thread_context.hpp>

// All project Boost.Asio translation units use the same pthread TSS backend
// on GNU/Linux via OpenProofCompileOptions.cmake.
template boost::asio::detail::tss_ptr<
    boost::asio::detail::call_stack<
        boost::asio::detail::thread_context,
        boost::asio::detail::thread_info_base>::context>
boost::asio::detail::call_stack<
    boost::asio::detail::thread_context,
    boost::asio::detail::thread_info_base>::top_;
