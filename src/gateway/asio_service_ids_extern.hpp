#pragma once

// GCC 16.2 may emit strong duplicate Asio service IDs at Debug optimization
// levels when module consumers instantiate the same execution_context service.
// Declare the three affected variables before any networking header can use
// them. The definitions live in a standalone, non-module translation unit.
// Release and other toolchains retain their original header-only linkage.
#if defined(OPENPROOF_ASIO_SINGLE_SERVICE_IDS)
#include <boost/asio/execution_context.hpp>
namespace boost::asio { class config_service; }
namespace boost::asio::detail { class scheduler; class epoll_reactor; }

extern template boost::asio::detail::service_id<boost::asio::config_service>
    boost::asio::detail::execution_context_service_base<boost::asio::config_service>::id;
extern template boost::asio::detail::service_id<boost::asio::detail::scheduler>
    boost::asio::detail::execution_context_service_base<boost::asio::detail::scheduler>::id;
extern template boost::asio::detail::service_id<boost::asio::detail::epoll_reactor>
    boost::asio::detail::execution_context_service_base<boost::asio::detail::epoll_reactor>::id;
#endif
