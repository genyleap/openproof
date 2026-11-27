// Ordinary C++ translation unit: these IDs identify the same Asio services
// in all module and non-module consumers. No linker override is required.
#include <boost/asio/execution_context.hpp>
namespace boost::asio { class config_service; }
namespace boost::asio::detail { class scheduler; class epoll_reactor; }

template boost::asio::detail::service_id<boost::asio::config_service>
    boost::asio::detail::execution_context_service_base<boost::asio::config_service>::id;
template boost::asio::detail::service_id<boost::asio::detail::scheduler>
    boost::asio::detail::execution_context_service_base<boost::asio::detail::scheduler>::id;
template boost::asio::detail::service_id<boost::asio::detail::epoll_reactor>
    boost::asio::detail::execution_context_service_base<boost::asio::detail::epoll_reactor>::id;
