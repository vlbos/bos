/**
 *  @file
 *  @copyright defined in bos/LICENSE.txt
 */

#include <eosio/chain/types.hpp>

#include <eosio/ibc_plugin/ibc_plugin.hpp>
#include <eosio/ibc_plugin/protocol.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/block.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>
#include <eosio/utilities/key_conversion.hpp>
#include <eosio/chain/contract_types.hpp>

#include <fc/network/message_buffer.hpp>
#include <fc/network/ip.hpp>
#include <fc/io/json.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/appender.hpp>
#include <fc/container/flat.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/exception/exception.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/intrusive/set.hpp>

using namespace eosio::chain::plugin_interface::compat;

namespace fc {
   extern std::unordered_map<std::string,logger>& get_logger_map();
}

namespace eosio { namespace ibc {
   static appbase::abstract_plugin& _ibc_plugin = app().register_plugin<ibc_plugin>();

   using std::vector;

   using boost::asio::ip::tcp;
   using boost::asio::ip::address_v4;
   using boost::asio::ip::host_name;
   using boost::intrusive::rbtree;
   using boost::multi_index_container;

   using fc::time_point;
   using fc::time_point_sec;
   using eosio::chain::transaction_id_type;
   namespace bip = boost::interprocess;

   class connection;

   class sync_manager;
   class dispatch_manager;

   using connection_ptr = std::shared_ptr<connection>;
   using connection_wptr = std::weak_ptr<connection>;

   using socket_ptr = std::shared_ptr<tcp::socket>;

   using ibc_message_ptr = shared_ptr<ibc_message>;
   
   class ibc_plugin_impl {
   public:
      unique_ptr<tcp::acceptor>        acceptor;
      tcp::endpoint                    listen_endpoint;
      string                           p2p_address;
      uint32_t                         max_client_count = 0;
      uint32_t                         max_nodes_per_host = 1;
      uint32_t                         num_clients = 0;

      vector<string>                   supplied_peers;
      vector<chain::public_key_type>   allowed_peers; ///< peer keys allowed to connect
      std::map<chain::public_key_type, chain::private_key_type> private_keys; ///< overlapping with producer keys, also authenticating non-producing nodes

      enum possible_connections : char {
         None = 0,
         Producers = 1 << 0,
         Specified = 1 << 1,
         Any = 1 << 2
      };
      possible_connections             allowed_connections{None};

      connection_ptr find_connection( string host )const;

      std::set< connection_ptr >       connections;
      bool                             done = false;
      unique_ptr< sync_manager >       sync_master;
      unique_ptr< dispatch_manager >   dispatcher;

      unique_ptr<boost::asio::steady_timer> connector_check;
      unique_ptr<boost::asio::steady_timer> contract_timer;
      unique_ptr<boost::asio::steady_timer> chain_check;
      unique_ptr<boost::asio::steady_timer> keepalive_timer;
      boost::asio::steady_timer::duration   connector_period;
      boost::asio::steady_timer::duration   txn_exp_period;
      boost::asio::steady_timer::duration   resp_expected_period;
      boost::asio::steady_timer::duration   keepalive_interval{std::chrono::seconds{5}};
      int                           max_cleanup_time_ms = 0;

      const std::chrono::system_clock::duration peer_authentication_interval{std::chrono::seconds{1}}; ///< Peer clock may be no more than 1 second skewed from our clock, including network latency.

      bool                          network_version_match = false;
      fc::sha256                    chain_id;
      fc::sha256                    remote_chain_id;
      fc::sha256                    node_id;

      string                        user_agent_name;
      chain_plugin*                 chain_plug = nullptr;
      int                           started_sessions = 0;

      shared_ptr<tcp::resolver>     resolver;

      bool                          use_socket_read_watermark = false;

      void connect( connection_ptr c );
      void connect( connection_ptr c, tcp::resolver::iterator endpoint_itr );
      bool start_session( connection_ptr c );
      void start_listen_loop( );
      void start_read_message( connection_ptr c);

      void   close( connection_ptr c );
      size_t count_open_sockets() const;

      template<typename VerifierFunc>
      void send_all( const ibc_message &msg, VerifierFunc verify );

      void accepted_block_header(const block_state_ptr&);
      void accepted_block(const block_state_ptr&);
      void irreversible_block(const block_state_ptr&);
      void accepted_transaction(const transaction_metadata_ptr&);
      void applied_transaction(const transaction_trace_ptr&);
      void accepted_confirmation(const header_confirmation&);

      bool is_valid( const handshake_message &msg);

      void handle_message( connection_ptr c, const handshake_message &msg);
      void handle_message( connection_ptr c, const go_away_message &msg );

      /** Process time_message
       * Calculate offset, delay and dispersion.  Note carefully the
       * implied processing.  The first-order difference is done
       * directly in 64-bit arithmetic, then the result is converted
       * to floating double.  All further processing is in
       * floating-double arithmetic with rounding done by the hardware.
       * This is necessary in order to avoid overflow and preserve precision.
       */
      void handle_message( connection_ptr c, const time_message &msg);

      void start_conn_timer( boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection );
      void start_monitors( );

      void connection_monitor(std::weak_ptr<connection> from_connection);

      /** Peer heartbeat ticker.
       */
      void ticker();
      bool authenticate_peer(const handshake_message& msg) const;

      /** Retrieve public key used to authenticate with peers.
       *
       * Finds a key to use for authentication.  If this node is a producer, use
       * the front of the producer key map.  If the node is not a producer but has
       * a configured private key, use it.  If the node is neither a producer nor has
       * a private key, returns an empty key.
       *
       * note: On a node with multiple private keys configured, the key with the first
       *       numerically smaller byte will always be used.
       */
      chain::public_key_type get_authentication_key() const;

      /** Returns a signature of the digest using the corresponding private key of the signer.
       * If there are no configured private keys, returns an empty signature.
       */
      chain::signature_type sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const;

      uint16_t to_protocol_version(uint16_t v);
   };

   const fc::string logger_name("ibc_plugin_impl");
   fc::logger logger;
   std::string peer_log_format;
      
#define peer_dlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::debug ) ) \
      logger.log( FC_LOG_MESSAGE( debug, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_ilog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::info ) ) \
      logger.log( FC_LOG_MESSAGE( info, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_wlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::warn ) ) \
      logger.log( FC_LOG_MESSAGE( warn, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_elog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::error ) ) \
      logger.log( FC_LOG_MESSAGE( error, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant())) ); \
  FC_MULTILINE_MACRO_END

   template<class enum_type, class=typename std::enable_if<std::is_enum<enum_type>::value>::type>
   inline enum_type& operator|=(enum_type& lhs, const enum_type& rhs)
   {
      using T = std::underlying_type_t <enum_type>;
      return lhs = static_cast<enum_type>(static_cast<T>(lhs) | static_cast<T>(rhs));
   }

   static ibc_plugin_impl *my_impl;

   /**
    * default value initializers
    */
   constexpr auto     def_send_buffer_size_mb = 4;
   constexpr auto     def_send_buffer_size = 1024*1024*def_send_buffer_size_mb;
   constexpr auto     def_max_clients = 25; // 0 for unlimited clients
   constexpr auto     def_max_nodes_per_host = 1;
   constexpr auto     def_conn_retry_wait = 30;
   constexpr auto     def_txn_expire_wait = std::chrono::seconds(3);
   constexpr auto     def_resp_expected_wait = std::chrono::seconds(5);
   constexpr auto     def_sync_fetch_span = 100;
   constexpr uint32_t  def_max_just_send = 1500; // roughly 1 "mtu"
   constexpr bool     large_msg_notify = false;

   constexpr auto     message_header_size = 4;

   /**
    *  For a while, network version was a 16 bit value equal to the second set of 16 bits
    *  of the current build's git commit id. We are now replacing that with an integer protocol
    *  identifier. Based on historical analysis of all git commit identifiers, the larges gap
    *  between ajacent commit id values is shown below.
    *  these numbers were found with the following commands on the master branch:
    *
    *  git log | grep "^commit" | awk '{print substr($2,5,4)}' | sort -u > sorted.txt
    *  rm -f gap.txt; prev=0; for a in $(cat sorted.txt); do echo $prev $((0x$a - 0x$prev)) $a >> gap.txt; prev=$a; done; sort -k2 -n gap.txt | tail
    *
    *  DO NOT EDIT ibc_version_base OR ibc_version_range!
    */
   constexpr uint16_t ibc_version_base = 0x04b5;
   constexpr uint16_t ibc_version_range = 106;
   /**
    *  If there is a change to network protocol or behavior, increment ibc version to identify
    *  the need for compatibility hooks
    */
   constexpr uint16_t proto_base = 0;
   constexpr uint16_t proto_explicit_sync = 1;

   constexpr uint16_t ibc_version = proto_explicit_sync;


   struct handshake_initializer {
      static void populate(handshake_message &hello);
   };
   
   class connection : public std::enable_shared_from_this<connection> {
   public:
      explicit connection( string endpoint );
      explicit connection( socket_ptr s );
      ~connection();
      void initialize();

      socket_ptr              socket;

      fc::message_buffer<1024*1024>    pending_message_buffer;
      fc::optional<std::size_t>        outstanding_read_bytes;

      struct queued_write {
         std::shared_ptr<vector<char>> buff;
         std::function<void(boost::system::error_code, std::size_t)> callback;
      };
      deque<queued_write>     write_queue;
      deque<queued_write>     out_queue;
      fc::sha256              node_id;
      handshake_message       last_handshake_recv;
      handshake_message       last_handshake_sent;
      int16_t                 sent_handshake_count = 0;
      bool                    connecting = false;
      bool                    syncing = false;
      uint16_t                protocol_version  = 0;
      string                  peer_addr;
      go_away_reason          no_retry = no_reason;
      block_id_type           fork_head;
      uint32_t                fork_head_num = 0;

      connection_status get_status()const {
         connection_status stat;
         stat.peer = peer_addr;
         stat.connecting = connecting;
         stat.syncing = syncing;
         stat.last_handshake = last_handshake_recv;
         return stat;
      }

      tstamp                         org{0};          //!< originate timestamp
      tstamp                         rec{0};          //!< receive timestamp
      tstamp                         dst{0};          //!< destination timestamp
      tstamp                         xmt{0};          //!< transmit timestamp

      double                         offset{0};       //!< peer offset

      static const size_t            ts_buffer_size{32};
      char                           ts[ts_buffer_size];   //!< working buffer for making human readable timestamps

      bool connected();
      bool current();
      void reset();
      void close();
      void send_handshake();

      /** \name Peer Timestamps
       *  Time message handling
       */
      /** @{ */
      /** \brief Convert an std::chrono nanosecond rep to a human readable string
       */
      char* convert_tstamp(const tstamp& t);
      /**  \brief Populate and queue time_message
       */
      void send_time();
      /** \brief Populate and queue time_message immediately using incoming time_message
       */
      void send_time(const time_message& msg);
      /** \brief Read system time and convert to a 64 bit integer.
       *
       * There are only two calls on this routine in the program.  One
       * when a packet arrives from the network and the other when a
       * packet is placed on the send queue.  Calls the kernel time of
       * day routine and converts to a (at least) 64 bit integer.
       */
      tstamp get_time()
      {
         return std::chrono::system_clock::now().time_since_epoch().count();
      }
      /** @} */

      const string peer_name();

      void txn_send_pending(const vector<transaction_id_type> &ids);
      void txn_send(const vector<transaction_id_type> &txn_lis);

      void blk_send_branch();
      void blk_send(const vector<block_id_type> &txn_lis);
      void stop_send();

      void enqueue( const ibc_message &msg, bool trigger_send = true );
      void cancel_sync(go_away_reason);
      void flush_queues();
      bool enqueue_sync_block();
      void request_sync_blocks (uint32_t start, uint32_t end);

      void cancel_wait();
      void sync_wait();
      void fetch_wait();
      void sync_timeout(boost::system::error_code ec);
      void fetch_timeout(boost::system::error_code ec);

      void queue_write(std::shared_ptr<vector<char>> buff,
                       bool trigger_send,
                       std::function<void(boost::system::error_code, std::size_t)> callback);
      void do_queue_write();

      /** \brief Process the next message from the pending message buffer
       *
       * Process the next message from the pending_message_buffer.
       * message_length is the already determined length of the data
       * part of the message and impl in the net plugin implementation
       * that will handle the message.
       * Returns true is successful. Returns false if an error was
       * encountered unpacking or processing the message.
       */
      bool process_next_message(ibc_plugin_impl& impl, uint32_t message_length);
      
//         fc::optional<fc::variant_object> _logger_variant;
//         const fc::variant_object& get_logger_variant()  {
//            if (!_logger_variant) {
//               boost::system::error_code ec;
//               auto rep = socket->remote_endpoint(ec);
//               string ip = ec ? "<unknown>" : rep.address().to_string();
//               string port = ec ? "<unknown>" : std::to_string(rep.port());
//
//               auto lep = socket->local_endpoint(ec);
//               string lip = ec ? "<unknown>" : lep.address().to_string();
//               string lport = ec ? "<unknown>" : std::to_string(lep.port());
//
//               _logger_variant.emplace(fc::mutable_variant_object()
//                                          ("_name", peer_name())
//                                          ("_id", node_id)
//                                          ("_sid", ((string)node_id).substr(0, 7))
//                                          ("_ip", ip)
//                                          ("_port", port)
//                                          ("_lip", lip)
//                                          ("_lport", lport)
//               );
//            }
//            return *_logger_variant;
//         }
   };
   
   struct msgHandler : public fc::visitor<void> {
      ibc_plugin_impl &impl;
      connection_ptr c;
      msgHandler( ibc_plugin_impl &imp, connection_ptr conn) : impl(imp), c(conn) {}

      template <typename T>
      void operator()(const T &msg) const
      {
         impl.handle_message( c, msg);
      }
   };

   class sync_manager {
      
   };

   class dispatch_manager {

   };



   //--------------- connection ---------------
   
   connection::connection(string endpoint)
      : socket(std::make_shared<tcp::socket>(std::ref(app().get_io_service()))),
        node_id(),
        last_handshake_recv(),
        last_handshake_sent(),
        sent_handshake_count(0),
        connecting(false),
        protocol_version(0),
        peer_addr(endpoint),
        no_retry(no_reason),
        fork_head(),
        fork_head_num(0) {
      wlog("created connection to ${n}", ("n", endpoint));
      initialize();
   }

   connection::connection( socket_ptr s )
      : socket( s ),
        node_id(),
        last_handshake_recv(),
        last_handshake_sent(),
        sent_handshake_count(0),
        connecting(true),
        protocol_version(0),
        peer_addr(),
        no_retry(no_reason),
        fork_head(),
        fork_head_num(0) {
      wlog( "accepted network connection" );
      initialize();
   }

   connection::~connection() {}


   void connection::initialize() {
      auto *rnd = node_id.data();
      rnd[0] = 0;
   }

   bool connection::connected() {
      return (socket && socket->is_open() && !connecting);
   }

   bool connection::current() {
      return (connected() && !syncing);
   }

   void connection::reset() {

   }

   void connection::flush_queues() {
      write_queue.clear();
   }

   void connection::close() {
      if(socket) {
         socket->close();
      }
      else {
         wlog("no socket to close!");
      }
      flush_queues();
      connecting = false;
      syncing = false;

      reset();
      sent_handshake_count = 0;
      last_handshake_recv = handshake_message();
      last_handshake_sent = handshake_message();
      fc_dlog(logger, "canceling wait on ${p}", ("p",peer_name()));
//      cancel_wait();
      pending_message_buffer.reset();
   }



   void connection::send_handshake( ) {
//      handshake_initializer::populate(last_handshake_sent);
//      last_handshake_sent.generation = ++sent_handshake_count;
//      fc_dlog(logger, "Sending handshake generation ${g} to ${ep}",
//              ("g",last_handshake_sent.generation)("ep", peer_name()));
//      enqueue(last_handshake_sent);
   }

   char* connection::convert_tstamp(const tstamp& t)
   {
      const long long NsecPerSec{1000000000};
      time_t seconds = t / NsecPerSec;
      strftime(ts, ts_buffer_size, "%F %T", localtime(&seconds));
      snprintf(ts+19, ts_buffer_size-19, ".%lld", t % NsecPerSec);
      return ts;
   }

   void connection::send_time() {
      time_message xpkt;
      xpkt.org = rec;
      xpkt.rec = dst;
      xpkt.xmt = get_time();
      org = xpkt.xmt;
      enqueue(xpkt);
   }

   void connection::send_time(const time_message& msg) {
      time_message xpkt;
      xpkt.org = msg.xmt;
      xpkt.rec = msg.dst;
      xpkt.xmt = get_time();
      enqueue(xpkt);
   }

   void connection::queue_write(std::shared_ptr<vector<char>> buff,
                                bool trigger_send,
                                std::function<void(boost::system::error_code, std::size_t)> callback) {
      write_queue.push_back({buff, callback});
      if(out_queue.empty() && trigger_send)
         do_queue_write();
   }

   void connection::do_queue_write() {
      if(write_queue.empty() || !out_queue.empty())
         return;
      connection_wptr c(shared_from_this());
      if(!socket->is_open()) {
         fc_elog(logger,"socket not open to ${p}",("p",peer_name()));
         my_impl->close(c.lock());
         return;
      }
      std::vector<boost::asio::const_buffer> bufs;
      while (write_queue.size() > 0) {
         auto& m = write_queue.front();
         bufs.push_back(boost::asio::buffer(*m.buff));
         out_queue.push_back(m);
         write_queue.pop_front();
      }
      boost::asio::async_write(*socket, bufs, [c](boost::system::error_code ec, std::size_t w) {
         try {
            auto conn = c.lock();
            if(!conn)
               return;

            for (auto& m: conn->out_queue) {
               m.callback(ec, w);
            }

            if(ec) {
               string pname = conn ? conn->peer_name() : "no connection name";
               if( ec.value() != boost::asio::error::eof) {
                  elog("Error sending to peer ${p}: ${i}", ("p",pname)("i", ec.message()));
               }
               else {
                  ilog("connection closure detected on write to ${p}",("p",pname));
               }
               my_impl->close(conn);
               return;
            }
            while (conn->out_queue.size() > 0) {
               conn->out_queue.pop_front();
            }
//            conn->enqueue_sync_block();
            conn->do_queue_write();
         }
         catch(const std::exception &ex) {
            auto conn = c.lock();
            string pname = conn ? conn->peer_name() : "no connection name";
            elog("Exception in do_queue_write to ${p} ${s}", ("p",pname)("s",ex.what()));
         }
         catch(const fc::exception &ex) {
            auto conn = c.lock();
            string pname = conn ? conn->peer_name() : "no connection name";
            elog("Exception in do_queue_write to ${p} ${s}", ("p",pname)("s",ex.to_string()));
         }
         catch(...) {
            auto conn = c.lock();
            string pname = conn ? conn->peer_name() : "no connection name";
            elog("Exception in do_queue_write to ${p}", ("p",pname) );
         }
      });
   }


   void connection::enqueue( const ibc_message &m, bool trigger_send ) {
      go_away_reason close_after_send = no_reason;
      if (m.contains<go_away_message>()) {
         close_after_send = m.get<go_away_message>().reason;
      }

      uint32_t payload_size = fc::raw::pack_size( m );
      char * header = reinterpret_cast<char*>(&payload_size);
      size_t header_size = sizeof(payload_size);

      size_t buffer_size = header_size + payload_size;

      auto send_buffer = std::make_shared<vector<char>>(buffer_size);
      fc::datastream<char*> ds( send_buffer->data(), buffer_size);
      ds.write( header, header_size );
      fc::raw::pack( ds, m );
      connection_wptr weak_this = shared_from_this();
      queue_write(send_buffer,trigger_send,
                  [weak_this, close_after_send](boost::system::error_code ec, std::size_t ) {
                     connection_ptr conn = weak_this.lock();
                     if (conn) {
                        if (close_after_send != no_reason) {
                           elog ("sent a go away message: ${r}, closing connection to ${p}",("r", reason_str(close_after_send))("p", conn->peer_name()));
                           my_impl->close(conn);
                           return;
                        }
                     } else {
                        fc_wlog(logger, "connection expired before enqueued ibc_message called callback!");
                     }
                  });
   }

   const string connection::peer_name() {
      if( !last_handshake_recv.p2p_address.empty() ) {
         return last_handshake_recv.p2p_address;
      }
      if( !peer_addr.empty() ) {
         return peer_addr;
      }
      return "connecting client";
   }

   bool connection::process_next_message(ibc_plugin_impl& impl, uint32_t message_length) {
      try {
         auto ds = pending_message_buffer.create_datastream();
         ibc_message msg;
         fc::raw::unpack(ds, msg);
         msgHandler m(impl, shared_from_this() );
         msg.visit(m);
      } catch(  const fc::exception& e ) {
         edump((e.to_detail_string() ));
         impl.close( shared_from_this() );
         return false;
      }
      return true;
   }









   //--------------- ibc_plugin_impl ---------------

   void ibc_plugin_impl::connect( connection_ptr c ) {
      if( c->no_retry != go_away_reason::no_reason) {
         fc_dlog( logger, "Skipping connect due to go_away reason ${r}",("r", reason_str( c->no_retry )));
         return;
      }

      auto colon = c->peer_addr.find(':');

      if (colon == std::string::npos || colon == 0) {
         elog ("Invalid peer address. must be \"host:port\": ${p}", ("p",c->peer_addr));
         for ( auto itr : connections ) {
            if((*itr).peer_addr == c->peer_addr) {
               (*itr).reset();
               close(itr);
               connections.erase(itr);
               break;
            }
         }
         return;
      }

      auto host = c->peer_addr.substr( 0, colon );
      auto port = c->peer_addr.substr( colon + 1);
      idump((host)(port));
      tcp::resolver::query query( tcp::v4(), host.c_str(), port.c_str() );
      connection_wptr weak_conn = c;
      // Note: need to add support for IPv6 too

      resolver->async_resolve( query,
                               [weak_conn, this]( const boost::system::error_code& err,
                                                  tcp::resolver::iterator endpoint_itr ){
                                  auto c = weak_conn.lock();
                                  if (!c) return;
                                  if( !err ) {
                                     connect( c, endpoint_itr );
                                  } else {
                                     elog( "Unable to resolve ${peer_addr}: ${error}",
                                           (  "peer_addr", c->peer_name() )("error", err.message() ) );
                                  }
                               });
   }

   void ibc_plugin_impl::connect( connection_ptr c, tcp::resolver::iterator endpoint_itr ) {
      if( c->no_retry != go_away_reason::no_reason) {
         string rsn = reason_str(c->no_retry);
         return;
      }
      auto current_endpoint = *endpoint_itr;
      ++endpoint_itr;
      c->connecting = true;
      connection_wptr weak_conn = c;
      c->socket->async_connect( current_endpoint, [weak_conn, endpoint_itr, this] ( const boost::system::error_code& err ) {
         auto c = weak_conn.lock();
         if (!c) return;
         if( !err && c->socket->is_open() ) {
            if (start_session( c )) {
               c->send_handshake ();
            }
         } else {
            if( endpoint_itr != tcp::resolver::iterator() ) {
               close(c);
               connect( c, endpoint_itr );
            }
            else {
               elog( "connection failed to ${peer}: ${error}",
                     ( "peer", c->peer_name())("error",err.message()));
               c->connecting = false;
               my_impl->close(c);
            }
         }
      } );
   }

   bool ibc_plugin_impl::start_session( connection_ptr con ) {
      boost::asio::ip::tcp::no_delay nodelay( true );
      boost::system::error_code ec;
      con->socket->set_option( nodelay, ec );
      if (ec) {
         elog( "connection failed to ${peer}: ${error}",
               ( "peer", con->peer_name())("error",ec.message()));
         con->connecting = false;
         close(con);
         return false;
      }
      else {
         start_read_message( con );
         ++started_sessions;
         return true;
      }
   }

   void ibc_plugin_impl::start_listen_loop( ) {
      auto socket = std::make_shared<tcp::socket>( std::ref( app().get_io_service() ) );
      acceptor->async_accept( *socket, [socket,this]( boost::system::error_code ec ) {
         if( !ec ) {
            uint32_t visitors = 0;
            uint32_t from_addr = 0;
            auto paddr = socket->remote_endpoint(ec).address();
            if (ec) {
               fc_elog(logger,"Error getting remote endpoint: ${m}",("m", ec.message()));
            }
            else {
               for (auto &conn : connections) {
                  if(conn->socket->is_open()) {
                     if (conn->peer_addr.empty()) {
                        visitors++;
                        boost::system::error_code ec;
                        if (paddr == conn->socket->remote_endpoint(ec).address()) {
                           from_addr++;
                        }
                     }
                  }
               }
               if (num_clients != visitors) {
                  ilog ("checking max client, visitors = ${v} num clients ${n}",("v",visitors)("n",num_clients));
                  num_clients = visitors;
               }
               if( from_addr < max_nodes_per_host && (max_client_count == 0 || num_clients < max_client_count )) {
                  ++num_clients;
                  connection_ptr c = std::make_shared<connection>( socket );
                  connections.insert( c );
                  start_session( c );

               }
               else {
                  if (from_addr >= max_nodes_per_host) {
                     fc_elog(logger, "Number of connections (${n}) from ${ra} exceeds limit",
                             ("n", from_addr+1)("ra",paddr.to_string()));
                  }
                  else {
                     fc_elog(logger, "Error max_client_count ${m} exceeded",
                             ( "m", max_client_count) );
                  }
                  socket->close( );
               }
            }
         } else {
            elog( "Error accepting connection: ${m}",( "m", ec.message() ) );
            // For the listed error codes below, recall start_listen_loop()
            switch (ec.value()) {
               case ECONNABORTED:
               case EMFILE:
               case ENFILE:
               case ENOBUFS:
               case ENOMEM:
               case EPROTO:
                  break;
               default:
                  return;
            }
         }
         start_listen_loop();
      });
   }

   void ibc_plugin_impl::start_read_message( connection_ptr conn ) {
      try {
         if(!conn->socket) {
            return;
         }
         connection_wptr weak_conn = conn;

         std::size_t minimum_read = conn->outstanding_read_bytes ? *conn->outstanding_read_bytes : message_header_size;

         if (use_socket_read_watermark) {
            const size_t max_socket_read_watermark = 4096;
            std::size_t socket_read_watermark = std::min<std::size_t>(minimum_read, max_socket_read_watermark);
            boost::asio::socket_base::receive_low_watermark read_watermark_opt(socket_read_watermark);
            conn->socket->set_option(read_watermark_opt);
         }

         auto completion_handler = [minimum_read](boost::system::error_code ec, std::size_t bytes_transferred) -> std::size_t {
            if (ec || bytes_transferred >= minimum_read ) {
               return 0;
            } else {
               return minimum_read - bytes_transferred;
            }
         };

         boost::asio::async_read(*conn->socket,
                                 conn->pending_message_buffer.get_buffer_sequence_for_boost_async_read(), completion_handler,
                                 [this,weak_conn]( boost::system::error_code ec, std::size_t bytes_transferred ) {
                                    auto conn = weak_conn.lock();
                                    if (!conn) {
                                       return;
                                    }

                                    conn->outstanding_read_bytes.reset();

                                    try {
                                       if( !ec ) {
                                          if (bytes_transferred > conn->pending_message_buffer.bytes_to_write()) {
                                             elog("async_read_some callback: bytes_transfered = ${bt}, buffer.bytes_to_write = ${btw}",
                                                  ("bt",bytes_transferred)("btw",conn->pending_message_buffer.bytes_to_write()));
                                          }
                                          EOS_ASSERT(bytes_transferred <= conn->pending_message_buffer.bytes_to_write(), plugin_exception, "");
                                          conn->pending_message_buffer.advance_write_ptr(bytes_transferred);
                                          while (conn->pending_message_buffer.bytes_to_read() > 0) {
                                             uint32_t bytes_in_buffer = conn->pending_message_buffer.bytes_to_read();

                                             if (bytes_in_buffer < message_header_size) {
                                                conn->outstanding_read_bytes.emplace(message_header_size - bytes_in_buffer);
                                                break;
                                             } else {
                                                uint32_t message_length;
                                                auto index = conn->pending_message_buffer.read_index();
                                                conn->pending_message_buffer.peek(&message_length, sizeof(message_length), index);
                                                if(message_length > def_send_buffer_size*2 || message_length == 0) {
                                                   boost::system::error_code ec;
                                                   elog("incoming message length unexpected (${i}), from ${p}", ("i", message_length)("p",boost::lexical_cast<std::string>(conn->socket->remote_endpoint(ec))));
                                                   close(conn);
                                                   return;
                                                }

                                                auto total_message_bytes = message_length + message_header_size;

                                                if (bytes_in_buffer >= total_message_bytes) {
                                                   conn->pending_message_buffer.advance_read_ptr(message_header_size);
                                                   if (!conn->process_next_message(*this, message_length)) {
                                                      return;
                                                   }
                                                } else {
                                                   auto outstanding_message_bytes = total_message_bytes - bytes_in_buffer;
                                                   auto available_buffer_bytes = conn->pending_message_buffer.bytes_to_write();
                                                   if (outstanding_message_bytes > available_buffer_bytes) {
                                                      conn->pending_message_buffer.add_space( outstanding_message_bytes - available_buffer_bytes );
                                                   }

                                                   conn->outstanding_read_bytes.emplace(outstanding_message_bytes);
                                                   break;
                                                }
                                             }
                                          }
                                          start_read_message(conn);
                                       } else {
                                          auto pname = conn->peer_name();
                                          if (ec.value() != boost::asio::error::eof) {
                                             elog( "Error reading message from ${p}: ${m}",("p",pname)( "m", ec.message() ) );
                                          } else {
                                             ilog( "Peer ${p} closed connection",("p",pname) );
                                          }
                                          close( conn );
                                       }
                                    }
                                    catch(const std::exception &ex) {
                                       string pname = conn ? conn->peer_name() : "no connection name";
                                       elog("Exception in handling read data from ${p} ${s}",("p",pname)("s",ex.what()));
                                       close( conn );
                                    }
                                    catch(const fc::exception &ex) {
                                       string pname = conn ? conn->peer_name() : "no connection name";
                                       elog("Exception in handling read data ${s}", ("p",pname)("s",ex.to_string()));
                                       close( conn );
                                    }
                                    catch (...) {
                                       string pname = conn ? conn->peer_name() : "no connection name";
                                       elog( "Undefined exception hanlding the read data from connection ${p}",( "p",pname));
                                       close( conn );
                                    }
                                 } );
      } catch (...) {
         string pname = conn ? conn->peer_name() : "no connection name";
         elog( "Undefined exception handling reading ${p}",("p",pname) );
         close( conn );
      }
   }

   size_t ibc_plugin_impl::count_open_sockets() const {
      size_t count = 0;
      for( auto &c : connections) {
         if(c->socket->is_open())
            ++count;
      }
      return count;
   }

   template<typename VerifierFunc>
   void ibc_plugin_impl::send_all( const ibc_message &msg, VerifierFunc verify) {
      for( auto &c : connections) {
         if( c->current() && verify( c)) {
            c->enqueue( msg );
         }
      }
   }

   bool ibc_plugin_impl::is_valid( const handshake_message &msg) {

   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const handshake_message &msg) {
      ilog("handle_message == handshake_message ");
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const go_away_message &msg ) {
      ilog("handle_message == go_away_message ");

   }

   void ibc_plugin_impl::handle_message(connection_ptr c, const time_message &msg) {
      ilog("handle_message == time_message ");

   }

   void ibc_plugin_impl::start_conn_timer(boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection) {
      connector_check->expires_from_now( du);
      connector_check->async_wait( [this, from_connection](boost::system::error_code ec) {
         if( !ec) {
            connection_monitor(from_connection);
         }
         else {
            elog( "Error from connection check monitor: ${m}",( "m", ec.message()));
            start_conn_timer( connector_period, std::weak_ptr<connection>());
         }
      });
   }

   void ibc_plugin_impl::ticker() {
      keepalive_timer->expires_from_now (keepalive_interval);
      keepalive_timer->async_wait ([this](boost::system::error_code ec) {
         ticker ();
         if (ec) {
            wlog ("Peer keepalive ticked sooner than expected: ${m}", ("m", ec.message()));
         }
         for (auto &c : connections ) {
            if (c->socket->is_open()) {
               c->send_time();
            }
         }
      });
   }

   void ibc_plugin_impl::start_monitors() {
      connector_check.reset(new boost::asio::steady_timer( app().get_io_service()));
      start_conn_timer(connector_period, std::weak_ptr<connection>());
   }

   void ibc_plugin_impl::connection_monitor(std::weak_ptr<connection> from_connection) {
      auto max_time = fc::time_point::now();
      max_time += fc::milliseconds(max_cleanup_time_ms);
      auto from = from_connection.lock();
      auto it = (from ? connections.find(from) : connections.begin());
      if (it == connections.end()) it = connections.begin();
      while (it != connections.end()) {
         if (fc::time_point::now() >= max_time) {
            start_conn_timer(std::chrono::milliseconds(1), *it); // avoid exhausting
            return;
         }
         if( !(*it)->socket->is_open() && !(*it)->connecting) {
            if( (*it)->peer_addr.length() > 0) {
               connect(*it);
            }
            else {
               it = connections.erase(it);
               continue;
            }
         }
         ++it;
      }
      start_conn_timer(connector_period, std::weak_ptr<connection>());
   }

   void ibc_plugin_impl::close( connection_ptr c ) {
      if( c->peer_addr.empty( ) && c->socket->is_open() ) {
         if (num_clients == 0) {
            fc_wlog( logger, "num_clients already at 0");
         }
         else {
            --num_clients;
         }
      }
      c->close();
   }

   void ibc_plugin_impl::accepted_block_header(const block_state_ptr& block) {
      fc_dlog(logger,"signaled, id = ${id}",("id", block->id));
      ilog ("======== 11 ===============");
   }

   void ibc_plugin_impl::accepted_block(const block_state_ptr& block) {
      fc_dlog(logger,"signaled, id = ${id}",("id", block->id));
//      dispatcher->bcast_block(*block->block);
      ilog ("======== 22 ===============");
   }

   void ibc_plugin_impl::irreversible_block(const block_state_ptr&block) {
      fc_dlog(logger,"signaled, id = ${id}",("id", block->id));
      ilog ("======== 33 ======33=========");
   }

   void ibc_plugin_impl::accepted_transaction(const transaction_metadata_ptr& md) {
      fc_dlog(logger,"signaled, id = ${id}",("id", md->id));
//      dispatcher->bcast_transaction(md->packed_trx);
      ilog ("======== 44 ===============");
   }

   void ibc_plugin_impl::applied_transaction(const transaction_trace_ptr& txn) {
      fc_dlog(logger,"signaled, id = ${id}",("id", txn->id));
      ilog ("======== 55 ===============");
   }

   void ibc_plugin_impl::accepted_confirmation(const header_confirmation& head) {
      fc_dlog(logger,"signaled, id = ${id}",("id", head.block_id));
      ilog ("======== 66 ===============");
   }

   bool ibc_plugin_impl::authenticate_peer(const handshake_message& msg) const {

   }

   chain::public_key_type ibc_plugin_impl::get_authentication_key() const {

   }

   chain::signature_type ibc_plugin_impl::sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const {

   }

   connection_ptr ibc_plugin_impl::find_connection( string host )const {
      for( const auto& c : connections )
         if( c->peer_addr == host ) return c;
      return connection_ptr();
   }

   uint16_t ibc_plugin_impl::to_protocol_version (uint16_t v) {
      if (v >= ibc_version_base) {
         v -= ibc_version_base;
         return (v > ibc_version_range) ? 0 : v;
      }
      return 0;
   }



   //--------------- handshake_initializer ---------------

   void handshake_initializer::populate( handshake_message &hello) {

   }



   //--------------- ibc_plugin ---------------

   ibc_plugin::ibc_plugin()
      :my( new ibc_plugin_impl ) {
      my_impl = my.get();
   }

   ibc_plugin::~ibc_plugin() {
   }

   void ibc_plugin::set_program_options( options_description& /*cli*/, options_description& cfg )
   {
      cfg.add_options()
         ( "ibc-listen-endpoint", bpo::value<string>()->default_value( "0.0.0.0:5678" ), "The actual host:port used to listen for incoming ibc connections.")
         ( "ibc-server-address", bpo::value<string>(), "An externally accessible host:port for identifying this node. Defaults to ibc-listen-endpoint.")
         ( "ibc-peer-address", bpo::value< vector<string> >()->composing(), "The public endpoint of a peer node to connect to. Use multiple ibc-peer-address options as needed to compose a network.")
         ( "ibc-max-nodes-per-host", bpo::value<int>()->default_value(def_max_nodes_per_host), "Maximum number of client nodes from any single IP address")
         ( "ibc-agent-name", bpo::value<string>()->default_value("\"BOS IBC Agent\""), "The name supplied to identify this node amongst the peers.")
         ( "ibc-allowed-connection", bpo::value<vector<string>>()->multitoken()->default_value({"any"}, "any"), "Can be 'any' or 'producers' or 'specified' or 'none'. If 'specified', peer-key must be specified at least once. If only 'producers', peer-key is not required. 'producers' and 'specified' may be combined.")
         ( "ibc-peer-key", bpo::value<vector<string>>()->composing()->multitoken(), "Optional public key of peer allowed to connect.  May be used multiple times.")
         ( "ibc-peer-private-key", boost::program_options::value<vector<string>>()->composing()->multitoken(), "Tuple of [PublicKey, WIF private key] (may specify multiple times)")
         ( "ibc-max-clients", bpo::value<int>()->default_value(def_max_clients), "Maximum number of clients from which connections are accepted, use 0 for no limit")
         ( "ibc-connection-cleanup-period", bpo::value<int>()->default_value(def_conn_retry_wait), "number of seconds to wait before cleaning up dead connections")
         ( "ibc-max-cleanup-time-msec", bpo::value<int>()->default_value(10), "max connection cleanup time per cleanup call in millisec")
         ( "ibc-version-match", bpo::value<bool>()->default_value(false), "True to require exact match of ibc plugin version.")
         ( "ibc-sync-fetch-span", bpo::value<uint32_t>()->default_value(def_sync_fetch_span), "number of blocks headers to retrieve in a chunk from any individual peer during synchronization")
         ( "ibc-use-socket-read-watermark", bpo::value<bool>()->default_value(false), "Enable expirimental socket read watermark optimization")
         ( "ibc-log-format", bpo::value<string>()->default_value( "[\"${_name}\" ${_ip}:${_port}]" ),
           "The string used to format peers when logging messages about them.  Variables are escaped with ${<variable name>}.\n"
           "Available Variables:\n"
           "   _name  \tself-reported name\n\n"
           "   _id    \tself-reported ID (64 hex characters)\n\n"
           "   _sid   \tfirst 8 characters of _peer.id\n\n"
           "   _ip    \tremote IP address of peer\n\n"
           "   _port  \tremote port number of peer\n\n"
           "   _lip   \tlocal IP address connected to peer\n\n"
           "   _lport \tlocal port number connected to peer\n\n")
         ;
   }

   template<typename T>
   T dejsonify(const string& s) {
      return fc::json::from_string(s).as<T>();
   }

   void ibc_plugin::plugin_initialize( const variables_map& options ) {
      ilog("Initialize ibc plugin");
      try {
         peer_log_format = options.at( "ibc-log-format" ).as<string>();

         my->network_version_match = options.at( "ibc-version-match" ).as<bool>();

//         my->sync_master.reset( new sync_manager( options.at( "ibc-sync-fetch-span" ).as<uint32_t>()));
         my->dispatcher.reset( new dispatch_manager );

         my->connector_period = std::chrono::seconds( options.at( "ibc-connection-cleanup-period" ).as<int>());
         my->max_cleanup_time_ms = options.at("ibc-max-cleanup-time-msec").as<int>();
         my->txn_exp_period = def_txn_expire_wait;
         my->resp_expected_period = def_resp_expected_wait;
         my->max_client_count = options.at( "ibc-max-clients" ).as<int>();
         my->max_nodes_per_host = options.at( "ibc-max-nodes-per-host" ).as<int>();
         my->num_clients = 0;
         my->started_sessions = 0;

         my->use_socket_read_watermark = options.at( "ibc-use-socket-read-watermark" ).as<bool>();

         my->resolver = std::make_shared<tcp::resolver>( std::ref( app().get_io_service()));

         if( options.count( "ibc-listen-endpoint" )) {
            my->p2p_address = options.at( "ibc-listen-endpoint" ).as<string>();
            auto host = my->p2p_address.substr( 0, my->p2p_address.find( ':' ));
            auto port = my->p2p_address.substr( host.size() + 1, my->p2p_address.size());
            idump((host)( port ));
            tcp::resolver::query query( tcp::v4(), host.c_str(), port.c_str());

            my->listen_endpoint = *my->resolver->resolve( query );
            my->acceptor.reset( new tcp::acceptor( app().get_io_service()));
         }

         if( options.count( "ibc-server-address" )) {
            my->p2p_address = options.at( "ibc-server-address" ).as<string>();
         } else {
            if( my->listen_endpoint.address().to_v4() == address_v4::any()) {
               boost::system::error_code ec;
               auto host = host_name( ec );
               if( ec.value() != boost::system::errc::success ) {
                  FC_THROW_EXCEPTION( fc::invalid_arg_exception, "Unable to retrieve host_name. ${msg}", ("msg", ec.message()));
               }
               auto port = my->p2p_address.substr( my->p2p_address.find( ':' ), my->p2p_address.size());
               my->p2p_address = host + port;
            }
         }

         if( options.count( "ibc-peer-address" )) {
            my->supplied_peers = options.at( "ibc-peer-address" ).as<vector<string> >();
         }

         if( options.count( "ibc-agent-name" )) {
            my->user_agent_name = options.at( "ibc-agent-name" ).as<string>();
         }

         if( options.count( "ibc-allowed-connection" )) {
            const std::vector<std::string> allowed_remotes = options["ibc-allowed-connection"].as<std::vector<std::string>>();
            for( const std::string& allowed_remote : allowed_remotes ) {
//               if( allowed_remote == "any" )
//                  my->allowed_connections |= ibc_plugin_impl::Any;
//               else if( allowed_remote == "producers" )
//                  my->allowed_connections |= ibc_plugin_impl::Producers;
//               else if( allowed_remote == "specified" )
//                  my->allowed_connections |= ibc_plugin_impl::Specified;
//               else if( allowed_remote == "none" )
//                  my->allowed_connections = ibc_plugin_impl::None;
            }
         }

         if( my->allowed_connections & ibc_plugin_impl::Specified )
            EOS_ASSERT( options.count( "ibc-peer-key" ), plugin_config_exception,
                        "At least one ibc-peer-key must accompany 'ibc-allowed-connection=specified'" );

         if( options.count( "ibc-peer-key" )) {
            const std::vector<std::string> key_strings = options["ibc-peer-key"].as<std::vector<std::string>>();
            for( const std::string& key_string : key_strings ) {
               my->allowed_peers.push_back( dejsonify<chain::public_key_type>( key_string ));
            }
         }

         if( options.count( "ibc-peer-private-key" )) {
            const std::vector<std::string> key_id_to_wif_pair_strings = options["ibc-peer-private-key"].as<std::vector<std::string>>();
            for( const std::string& key_id_to_wif_pair_string : key_id_to_wif_pair_strings ) {
               auto key_id_to_wif_pair = dejsonify<std::pair<chain::public_key_type, std::string>>(
                  key_id_to_wif_pair_string );
               my->private_keys[key_id_to_wif_pair.first] = fc::crypto::private_key( key_id_to_wif_pair.second );
            }
         }

         my->chain_plug = app().find_plugin<chain_plugin>();
         EOS_ASSERT( my->chain_plug, chain::missing_chain_plugin_exception, "" );
         my->chain_id = app().get_plugin<chain_plugin>().get_chain_id();

//         my->node_id = ;

         my->keepalive_timer.reset( new boost::asio::steady_timer( app().get_io_service()));
         my->ticker();
      } FC_LOG_AND_RETHROW()
   }

   void ibc_plugin::plugin_startup() {
      if( my->acceptor ) {
         my->acceptor->open(my->listen_endpoint.protocol());
         my->acceptor->set_option(tcp::acceptor::reuse_address(true));
         try {
            my->acceptor->bind(my->listen_endpoint);
         } catch (const std::exception& e) {
            ilog("ibc_plugin::plugin_startup failed to bind to port ${port}", ("port", my->listen_endpoint.port()));
            throw e;
         }
         my->acceptor->listen();
         ilog("starting ibc plugin listener, max clients is ${mc}",("mc",my->max_client_count));
         my->start_listen_loop();
      }
      chain::controller&cc = my->chain_plug->chain();
      cc.irreversible_block.connect( boost::bind(&ibc_plugin_impl::irreversible_block, my.get(), _1));

      my->start_monitors();

      for( auto seed_node : my->supplied_peers ) {
         connect( seed_node );
      }

      if(fc::get_logger_map().find(logger_name) != fc::get_logger_map().end())
         logger = fc::get_logger_map()[logger_name];
   }

   void ibc_plugin::plugin_shutdown() {
      try {
         ilog( "shutdown.." );
         my->done = true;
         if( my->acceptor ) {
            ilog( "close acceptor" );
            my->acceptor->close();

            ilog( "close ${s} connections",( "s",my->connections.size()) );
            auto cons = my->connections;
            for( auto con : cons ) {
               my->close( con);
            }

            my->acceptor.reset(nullptr);
         }
         ilog( "exit shutdown" );
      }
      FC_CAPTURE_AND_RETHROW()
   }

   size_t ibc_plugin::num_peers() const {
      return my->count_open_sockets();
   }

   /**
    *  Used to trigger a new connection from RPC API
    */
   string ibc_plugin::connect( const string& host ) {
      if( my->find_connection( host ) )
         return "already connected";

      connection_ptr c = std::make_shared<connection>(host);
      fc_dlog(logger,"adding new connection to the list");
      my->connections.insert( c );
      fc_dlog(logger,"calling active connector");
      my->connect( c );
      return "added connection";
   }

   string ibc_plugin::disconnect( const string& host ) {
      for( auto itr = my->connections.begin(); itr != my->connections.end(); ++itr ) {
         if( (*itr)->peer_addr == host ) {
            (*itr)->reset();
            my->close(*itr);
            my->connections.erase(itr);
            return "connection removed";
         }
      }
      return "no known connection for host";
   }

   optional<connection_status> ibc_plugin::status( const string& host )const {
      auto con = my->find_connection( host );
      if( con )
         return con->get_status();
      return optional<connection_status>();
   }

   vector<connection_status> ibc_plugin::connections()const {
      vector<connection_status> result;
      result.reserve( my->connections.size() );
      for( const auto& c : my->connections ) {
         result.push_back( c->get_status() );
      }
      return result;
   }

}}