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
   using eosio::chain::name;
   using mvo = fc::mutable_variant_object;
   namespace bip = boost::interprocess;

   class connection;

   class sync_manager;
   class dispatch_manager;
   class ibc_contract;

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
         Specified = 1 << 0,
         Any = 1 << 1
      };
      possible_connections             allowed_connections{None};

      connection_ptr find_connection( string host )const;

      std::set< connection_ptr >       connections;
      bool                             done = false;
      unique_ptr< sync_manager >       sync_master;
      unique_ptr< dispatch_manager >   dispatcher;
      unique_ptr< ibc_contract >       contract;
      ibc_contract_state               contract_state = none;

      unique_ptr<boost::asio::steady_timer> connector_check;
      unique_ptr<boost::asio::steady_timer> ibc_contract_check;
      unique_ptr<boost::asio::steady_timer> chain_check;
      unique_ptr<boost::asio::steady_timer> keepalive_timer;
      boost::asio::steady_timer::duration   connector_period;
      boost::asio::steady_timer::duration   ibc_contract_interval{std::chrono::seconds{5}};
      boost::asio::steady_timer::duration   chain_interval{std::chrono::seconds{5}};
      boost::asio::steady_timer::duration   keepalive_interval{std::chrono::seconds{5}};
      int                           max_cleanup_time_ms = 0;

      const std::chrono::system_clock::duration peer_authentication_interval{std::chrono::seconds{1}}; ///< Peer clock may be no more than 1 second skewed from our clock, including network latency.

      bool                          network_version_match = false;
      fc::sha256                    chain_id;
      fc::sha256                    sidechain_id;
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
      void start_read_message( connection_ptr c );

      void   close( connection_ptr c );
      size_t count_open_sockets() const;

      template<typename VerifierFunc>
      void send_all( const ibc_message &msg, VerifierFunc verify );

      void accepted_block_header(const block_state_ptr&);
      void accepted_block(const block_state_ptr&);
      void irreversible_block(const block_state_ptr&);
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

      void handle_message( connection_ptr c, const lwc_heartbeat_message &msg);
      void handle_message( connection_ptr c, const request_lwcls_message &msg);
      void handle_message( connection_ptr c, const lwcls_detail_message &msg);
      void handle_message( connection_ptr c, const lwc_init_message &msg);
      void handle_message( connection_ptr c, const lwc_section_data &msg);
      void handle_message( connection_ptr c, const lwc_ibctrx_data &msg);
      void handle_message( connection_ptr c, const notice_lwc_block_message &msg);
      void handle_message( connection_ptr c, const lwc_request_message &msg);


      void start_conn_timer( boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection );
      void start_ibc_contract_timer( );
      void start_chain_timer( );
      void start_monitors( );

      void connection_monitor(std::weak_ptr<connection> from_connection);

      /** Peer heartbeat ticker.
       */
      void ticker();
      void chain_checker();
      void ibc_contract_checker();
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
    *  If there is a change to network protocol or behavior, increment net version to identify
    *  the need for compatibility hooks
    */
   constexpr uint16_t net_version = 1;


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
      uint16_t                protocol_version  = 0;
      string                  peer_addr;
      unique_ptr<boost::asio::steady_timer> response_expected;
      go_away_reason          no_retry = no_reason;

      connection_status get_status()const {
         connection_status stat;
         stat.peer = peer_addr;
         stat.connecting = connecting;
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

      void enqueue( const ibc_message &msg, bool trigger_send = true );
      void flush_queues();

      void cancel_wait();
//      void sync_wait();
//      void sync_timeout(boost::system::error_code ec);

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
      
      fc::optional<fc::variant_object> _logger_variant;
      const fc::variant_object& get_logger_variant()  {
         if (!_logger_variant) {
            boost::system::error_code ec;
            auto rep = socket->remote_endpoint(ec);
            string ip = ec ? "<unknown>" : rep.address().to_string();
            string port = ec ? "<unknown>" : std::to_string(rep.port());

            auto lep = socket->local_endpoint(ec);
            string lip = ec ? "<unknown>" : lep.address().to_string();
            string lport = ec ? "<unknown>" : std::to_string(lep.port());

            _logger_variant.emplace(fc::mutable_variant_object()
                                       ("_name", peer_name())
                                       ("_id", node_id)
                                       ("_sid", ((string)node_id).substr(0, 7))
                                       ("_ip", ip)
                                       ("_port", port)
                                       ("_lip", lip)
                                       ("_lport", lport)
            );
         }
         return *_logger_variant;
      }
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
   public:

      enum stages {
         normal,
         in_get_lwc_last_section,
         in_sync_to_lwc
      };

      std::vector<std::pair<uint32_t,block_id_type>> lwc_last_section;


      uint32_t    lwc_ls_first;  // light weight client last section first block number.
      uint32_t    lwc_ls_last;
      uint32_t    lwc_ls_lib;



      void get_lwc_last_section();
      void get_lwc_last_section_ids();
      void append_lwc_last_section();
      void new_lwc_section();


   };
   
   // contract related functions

   optional<key_value_object>  get_table_reverse_nth_row_obj( const name& code, const name& scope, const name& table, const uint64_t nth = 0 ) {
      const auto& d = app().get_plugin<chain_plugin>().chain().db();
      const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(code, scope, table));
      if (t_id != nullptr) {
         const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
         decltype(t_id->id) next_tid(t_id->id._id + 1);
         auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
         auto upper = idx.lower_bound(boost::make_tuple(next_tid));

         if ( lower == upper ){
            return optional<key_value_object>();
         }

         --upper;

         int i = nth;
         auto itr = upper;
         for (; itr != lower && i >= 0; --itr) {
            if (i == 0) {
               const key_value_object &obj = *itr;
               return obj;
            }
            --i;
         }

         if ( i == 0 && itr == lower ){
            return *lower;
         }
      }
      return optional<key_value_object>();
   }

   optional<key_value_object>  get_singleton( const name& code, const name& scope, const name& table ) {
      const auto &d = app().get_plugin<chain_plugin>().chain().db();
      const auto *t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(
         boost::make_tuple(code, scope, table));
      if (t_id != nullptr) {
         const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
         decltype(t_id->id) next_tid(t_id->id._id + 1);
         auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
         auto upper = idx.lower_bound(boost::make_tuple(next_tid));

         if (lower == upper) {
            return optional<key_value_object>();
         }
         return *lower;
      }
      return optional<key_value_object>();
   }

   static const uint32_t default_expiration_delta = 30;  ///< 30 seconds
   static const fc::microseconds abi_serializer_max_time{500 * 1000};   ///< 500ms
   
   void set_transaction_headers( transaction& trx, uint32_t expiration = default_expiration_delta, uint32_t delay_sec = 0 ) {
      trx.expiration = my_impl->chain_plug->chain().head_block_time() + fc::seconds(expiration);
      trx.set_reference_block( my_impl->chain_plug->chain().last_irreversible_block_id() );

      trx.max_net_usage_words = 0; // No limit
      trx.max_cpu_usage_ms = 0; // No limit
      trx.delay_sec = delay_sec;
   }

   action get_action( account_name code, action_name acttype, vector<permission_level> auths, const bytes& data ) {
         action act;
         act.account = code;
         act.name = acttype;
         act.authorization = auths;
         act.data = data;
         return act;
   }

   void push_transaction( signed_transaction& trx ) {
      auto next = [](const fc::static_variant<fc::exception_ptr, chain_apis::read_write::push_transaction_results>& result){
         if (result.contains<fc::exception_ptr>()) {
            try {
               result.get<fc::exception_ptr>()->dynamic_rethrow_exception();
            } catch (...) {
              elog("push_transaction failed");
            }
         } else {
            auto trx_id = result.get<chain_apis::read_write::push_transaction_results>().transaction_id;
            ilog("pushed transaction: ${id}", ( "id", trx_id ));
         }
      };

      my_impl->chain_plug->get_read_write_api().push_transaction( mvo()("packed_trx", packed_transaction(trx)), next );
   }

   bool push_action( action actn ) {
      if ( my_impl->private_keys.empty() ){
         wlog("ibc contract account active key not found, can not execute action");
         return false;
      }

      signed_transaction trx;
      trx.actions.emplace_back( actn );
      set_transaction_headers( trx );
      trx.sign( my_impl->private_keys.begin()->second, my_impl->chain_plug->chain().get_chain_id() );
      push_transaction( trx );
   }


#define min_lwc_lib_depth 50
#define max_lwc_lib_depth 200
   
   
   class ibc_contract {
   public:
      ibc_contract(  name contract );

      // actions
      void chain_init( const lwc_init_message &msg );
      void newsection();
      void addheaders();

      // tables
      optional<section_type> get_table_sections_reverse_nth( uint64_t nth = 0 );
      optional<global_state> get_global_singleton();

      // others
      void get_basic_info();
      bool lib_depth_valid();

      
      uint32_t lwc_lib_depth = 0;
      
   private:
      bool has_contract();
      bool initialized();
      
   private:
      name account;
   };

   //--------------- ibc_contract ---------------

   ibc_contract::ibc_contract( name contract ){
      account = contract;
   }

   bool ibc_contract::has_contract(){
      auto ro_api = app().get_plugin<chain_plugin>().get_read_only_api();
      eosio::chain_apis::read_only::get_code_hash_params params{account};
      try {
         auto result = ro_api.get_code_hash( params );
         if ( result.code_hash != fc::sha256() ){
            return true;
         }
      } catch (...){}
      return false;
   }

   bool ibc_contract::initialized(){
      auto ret = get_table_sections_reverse_nth();
      if ( ret.valid() ){
         return true;
      }
      return false;
   }

   
   void ibc_contract::get_basic_info(){
      ibc_contract_state state = none;
      if ( has_contract() ){
         state = deployed;
         if ( initialized() ){
            state = working;
         }
      }
      my_impl->contract_state = state;

      global_state gstate;
      auto sp = get_global_singleton();
      if ( sp.valid() ) {
         gstate = *sp;
         lwc_lib_depth = gstate.lib_depth;
      }
   }

   bool ibc_contract::lib_depth_valid(){
      if ( lwc_lib_depth >= min_lwc_lib_depth && lwc_lib_depth <= max_lwc_lib_depth ){
         return true;
      }
      return false;
   }

   optional<section_type> ibc_contract::get_table_sections_reverse_nth( uint64_t nth ){
      auto p = get_table_reverse_nth_row_obj( account, account, N(sections), nth );
      if ( p.valid() ){
         auto obj = *p;
         fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
         section_type result;
         fc::raw::unpack( ds, result );
         return result;
      }
      return optional<section_type>();
   }

   optional<global_state> ibc_contract::get_global_singleton(){
      auto p = get_singleton( account, account, N(global) );
      if ( p.valid() ){
         auto obj = *p;
         fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
         global_state result;
         fc::raw::unpack( ds, result );
         return result;
      }
      return optional<global_state>();
   }


   void ibc_contract::chain_init( const lwc_init_message &msg ){


      auto str = fc::json::to_string( mvo()
         ("header",           msg.header)
         ("active_schedule",  msg.active_schedule)
         ("blockroot_merkle", msg.blockroot_merkle));

      bytes data( str.begin(), str.end() );
      auto actn = get_action( account, N(chaininit), vector<permission_level>{{ account, config::active_name}}, data );

      if ( !push_action( actn ) ){
         elog("push_action failed");
      }
   }

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
        response_expected(),
        no_retry(no_reason)
   {
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
        response_expected(),
        no_retry(no_reason)
   {
      wlog( "accepted network connection" );
      initialize();
   }

   connection::~connection() {}


   void connection::initialize() {
      auto *rnd = node_id.data();
      rnd[0] = 0;
      response_expected.reset(new boost::asio::steady_timer(app().get_io_service()));
   }

   bool connection::connected() {
      return (socket && socket->is_open() && !connecting);
   }

   bool connection::current() {
      return connected();
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

      reset();
      sent_handshake_count = 0;
      last_handshake_recv = handshake_message();
      last_handshake_sent = handshake_message();
      fc_dlog(logger, "canceling wait on ${p}", ("p",peer_name()));
      cancel_wait();
      pending_message_buffer.reset();
   }



   void connection::send_handshake( ) {
      handshake_initializer::populate(last_handshake_sent);
      last_handshake_sent.generation = ++sent_handshake_count;
      fc_dlog(logger, "Sending handshake generation ${g} to ${ep}",
              ("g",last_handshake_sent.generation)("ep", peer_name()));
      enqueue(last_handshake_sent);
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

   void connection::cancel_wait() {
      if (response_expected)
         response_expected->cancel();
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
      // Do some basic validation of an incoming handshake_message, so things
      // that really aren't handshake messages can be quickly discarded without
      // affecting state.
      bool valid = true;
      if (msg.last_irreversible_block_num > msg.head_num) {
         wlog("Handshake message validation: last irreversible block (${i}) is greater than head block (${h})",
              ("i", msg.last_irreversible_block_num)("h", msg.head_num));
         valid = false;
      }
      if (msg.p2p_address.empty()) {
         wlog("Handshake message validation: p2p_address is null string");
         valid = false;
      }
      if (msg.os.empty()) {
         wlog("Handshake message validation: os field is null string");
         valid = false;
      }
      if ((msg.sig != chain::signature_type() || msg.token != sha256()) && (msg.token != fc::sha256::hash(msg.time))) {
         wlog("Handshake message validation: token field invalid");
         valid = false;
      }
      return valid;
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const handshake_message &msg) {
      peer_ilog(c, "received handshake_message");
      if (!is_valid(msg)) {
         peer_elog( c, "bad handshake message");
         c->enqueue( go_away_message( fatal_other ));
         return;
      }

      if( c->connecting ) {
         c->connecting = false;
      }
      if (msg.generation == 1) {
         if( msg.node_id == node_id) {
            elog( "Self connection detected. Closing connection");
            c->enqueue( go_away_message( self ) );
            return;
         }

         if( c->peer_addr.empty() || c->last_handshake_recv.node_id == fc::sha256()) {
            fc_dlog(logger, "checking for duplicate" );
            for(const auto &check : connections) {
               if(check == c)
                  continue;
               if(check->connected() && check->peer_name() == msg.p2p_address) {
                  // It's possible that both peers could arrive here at relatively the same time, so
                  // we need to avoid the case where they would both tell a different connection to go away.
                  // Using the sum of the initial handshake times of the two connections, we will
                  // arbitrarily (but consistently between the two peers) keep one of them.
                  if (msg.time + c->last_handshake_sent.time <= check->last_handshake_sent.time + check->last_handshake_recv.time)
                     continue;

                  fc_dlog( logger, "sending go_away duplicate to ${ep}", ("ep",msg.p2p_address) );
                  go_away_message gam(duplicate);
                  gam.node_id = node_id;
                  c->enqueue(gam);
                  c->no_retry = duplicate;
                  return;
               }
            }
         }
         else {
            fc_dlog(logger, "skipping duplicate check, addr == ${pa}, id = ${ni}",("pa",c->peer_addr)("ni",c->last_handshake_recv.node_id));
         }

//         if( msg.chain_id != sidechain_id) {
//            elog( "Peer chain id not correct. Closing connection");
//            c->enqueue( go_away_message(go_away_reason::wrong_chain) );
//            return;
//         }
         c->protocol_version = to_protocol_version(msg.network_version);
         if(c->protocol_version != net_version) {
            if (network_version_match) {
               elog("Peer network version does not match expected ${nv} but got ${mnv}",
                    ("nv", net_version)("mnv", c->protocol_version));
               c->enqueue(go_away_message(wrong_version));
               return;
            } else {
               ilog("Local network version: ${nv} Remote version: ${mnv}",
                    ("nv", net_version)("mnv", c->protocol_version));
            }
         }

         if(  c->node_id != msg.node_id) {
            c->node_id = msg.node_id;
         }

         if(!authenticate_peer(msg)) {
            elog("Peer not authenticated.  Closing connection.");
            c->enqueue(go_away_message(authentication));
            return;
         }

         if (c->sent_handshake_count == 0) {
            c->send_handshake();
         }
      }

      c->last_handshake_recv = msg;
      c->_logger_variant.reset();
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const go_away_message &msg ) {
      string rsn = reason_str( msg.reason );
      peer_ilog(c, "received go_away_message");
      ilog( "received a go away message from ${p}, reason = ${r}",
            ("p", c->peer_name())("r",rsn));
      c->no_retry = msg.reason;
      if(msg.reason == duplicate ) {
         c->node_id = msg.node_id;
      }
      c->flush_queues();
      close (c);
   }

   void ibc_plugin_impl::handle_message(connection_ptr c, const time_message &msg) {
      peer_ilog(c, "received time_message");
      /* We've already lost however many microseconds it took to dispatch
       * the message, but it can't be helped.
       */
      msg.dst = c->get_time();

      // If the transmit timestamp is zero, the peer is horribly broken.
      if(msg.xmt == 0)
         return;                 /* invalid timestamp */

      if(msg.xmt == c->xmt)
         return;                 /* duplicate packet */

      c->xmt = msg.xmt;
      c->rec = msg.rec;
      c->dst = msg.dst;

      if(msg.org == 0)
      {
         c->send_time(msg);
         return;  // We don't have enough data to perform the calculation yet.
      }

      c->offset = (double(c->rec - c->org) + double(msg.xmt - c->dst)) / 2;
      double NsecPerUsec{1000};

      if(logger.is_enabled(fc::log_level::all))
         logger.log(FC_LOG_MESSAGE(all, "Clock offset is ${o}ns (${us}us)", ("o", c->offset)("us", c->offset/NsecPerUsec)));
      c->org = 0;
      c->rec = 0;
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_heartbeat_message &msg) {
      peer_ilog(c, "received lwc_heartbeat_message");

      if ( msg.state == deployed ) {
         // 发送初始化
         controller &cc = chain_plug->chain();
         uint32_t head_num = cc.fork_db_head_block_num();
         uint32_t depth = 200;
         block_state_ptr p = cc.fetch_block_state_by_number( head_num - depth );

         while ( p == block_state_ptr() && depth >= 10 ){
            depth /= 2;
            block_state_ptr p = cc.fetch_block_state_by_number( head_num - depth );
            ilog("didn't get block_state_ptr of block num: ${n}", ("n", head_num - depth ));
         }

         if ( p == block_state_ptr() ){
            ilog("didn't get any block state finally");
            return;
         }

         if ( p->pending_schedule.version != p->active_schedule.version ){
            ilog("pending_schedule version not equal to active_schedule version, wait until equal");
            return;
         }

         lwc_init_message msg;
         msg.header = p->header;
         msg.active_schedule = p->active_schedule;
         msg.blockroot_merkle = p->blockroot_merkle;

         ilog("send lwc_init_message");
         c->enqueue( msg, true);
      }
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const request_lwcls_message &msg) {
      peer_ilog(c, "received request_lwcls_message");
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwcls_detail_message &msg) {
      peer_ilog(c, "received lwcls_detail_message");
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_init_message &msg) {
      peer_ilog(c, "received lwc_init_message");

      contract->get_basic_info();
      if ( contract_state == deployed && contract->lib_depth_valid() ){
         contract->chain_init( msg );
      }
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_section_data &msg) {
      peer_ilog(c, "received lwc_section_data");
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_ibctrx_data &msg) {
      peer_ilog(c, "received lwc_ibctrx_data");
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const notice_lwc_block_message &msg) {
      peer_ilog(c, "received notice_lwc_block_message");
   }

   void ibc_plugin_impl::handle_message( connection_ptr c, const lwc_request_message &msg) {
      peer_ilog(c, "received lwc_request_message");
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

   void ibc_plugin_impl::start_ibc_contract_timer() {
      ibc_contract_checker();
      ibc_contract_check->expires_from_now (ibc_contract_interval);
      ibc_contract_check->async_wait ([this](boost::system::error_code ec) {
         start_ibc_contract_timer();
         if (ec) {
            wlog ("start_ibc_contract_timer error: ${m}", ("m", ec.message()));
         }
      });
   }

   void ibc_plugin_impl::ibc_contract_checker() {
      if ( contract_state == none ){
         wlog("ibc contract does not exist");
         contract->get_basic_info();
         return;
      }

      if ( !contract->lib_depth_valid() ){
         wlog("ibc contract global singleton config lib_depth not valid");
         contract->get_basic_info();
         return;
      }

      ilog("++++++++++++========");

      lwc_heartbeat_message msg;
      msg.state = contract_state;

      if ( contract_state != deployed ){
         auto p = my_impl->contract->get_table_sections_reverse_nth();
         if ( p.valid() ){
            auto obj = *p;
            msg.ls_first_num = obj.first;
//            msg.ls_first_id = ;
            msg.ls_last_num = obj.last;
//            msg.ls_last_id = ;
            msg.ls_lib_num = std::max( obj.last - contract->lwc_lib_depth, obj.first );
//            msg.ls_lib_id = ;
            msg.ls_valid = obj.valid;
         }
      }

      for (auto &c : connections ) {
         if (c->socket->is_open()) {
            c->enqueue( msg, true);
         }
      }
   }

   void ibc_plugin_impl::start_chain_timer() {
      chain_checker();
      chain_check->expires_from_now (chain_interval);
      chain_check->async_wait ([this](boost::system::error_code ec) {
         start_chain_timer();
         if (ec) {
            wlog ("start_chain_timer error: ${m}", ("m", ec.message()));
         }
      });
   }

   void ibc_plugin_impl::chain_checker() {
      /**
       * 检查是否是跟上状态
       *
       * 实时监控bp列表是否有变化
       * 至少每个小时同步一次数据
       */
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
      ibc_contract_check.reset(new boost::asio::steady_timer( app().get_io_service()));
      chain_check.reset(new boost::asio::steady_timer( app().get_io_service()));

      start_conn_timer(connector_period, std::weak_ptr<connection>());
      start_ibc_contract_timer();
      start_chain_timer();
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
   }

   void ibc_plugin_impl::accepted_block(const block_state_ptr& block) {
      fc_dlog(logger,"signaled, id = ${id}",("id", block->id));
   }

   void ibc_plugin_impl::irreversible_block(const block_state_ptr&block) {
      fc_dlog(logger,"signaled, id = ${id}",("id", block->id));
      // 每小时记录一个blockmroot
   }

   void ibc_plugin_impl::accepted_confirmation(const header_confirmation& head) {
      fc_dlog(logger,"signaled, id = ${id}",("id", head.block_id));
   }

   bool ibc_plugin_impl::authenticate_peer(const handshake_message& msg) const {
      if(allowed_connections == None)
         return false;

      if(allowed_connections == Any)
         return true;

      if(allowed_connections == Specified) {
         auto allowed_it = std::find(allowed_peers.begin(), allowed_peers.end(), msg.key);
         auto private_it = private_keys.find(msg.key);

         if( allowed_it == allowed_peers.end() && private_it == private_keys.end() ) {
            elog( "Peer ${peer} sent a handshake with an unauthorized key: ${key}.",
                  ("peer", msg.p2p_address)("key", msg.key));
            return false;
         }
      }

      namespace sc = std::chrono;
      sc::system_clock::duration msg_time(msg.time);
      auto time = sc::system_clock::now().time_since_epoch();
      if(time - msg_time > peer_authentication_interval) {
         elog( "Peer ${peer} sent a handshake with a timestamp skewed by more than ${time}.",
               ("peer", msg.p2p_address)("time", "1 second")); // TODO Add to_variant for std::chrono::system_clock::duration
         return false;
      }

      if(msg.sig != chain::signature_type() && msg.token != sha256()) {
         sha256 hash = fc::sha256::hash(msg.time);
         if(hash != msg.token) {
            elog( "Peer ${peer} sent a handshake with an invalid token.",
                  ("peer", msg.p2p_address));
            return false;
         }
         chain::public_key_type peer_key;
         try {
            peer_key = crypto::public_key(msg.sig, msg.token, true);
         }
         catch (fc::exception& /*e*/) {
            elog( "Peer ${peer} sent a handshake with an unrecoverable key.",
                  ("peer", msg.p2p_address));
            return false;
         }
         if((allowed_connections & Specified) && peer_key != msg.key) {
            elog( "Peer ${peer} sent a handshake with an unauthenticated key.",
                  ("peer", msg.p2p_address));
            return false;
         }
      }
      else if(allowed_connections & Specified) {
         dlog( "Peer sent a handshake with blank signature and token, but this node accepts only authenticated connections.");
         return false;
      }
      return true;
   }

   chain::public_key_type ibc_plugin_impl::get_authentication_key() const {
      if(!private_keys.empty())
         return private_keys.begin()->first;
      return chain::public_key_type();
   }

   chain::signature_type ibc_plugin_impl::sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const {
      auto private_key_itr = private_keys.find(signer);
      if(private_key_itr != private_keys.end())
         return private_key_itr->second.sign(digest);
      return chain::signature_type();
   }

   connection_ptr ibc_plugin_impl::find_connection( string host )const {
      for( const auto& c : connections )
         if( c->peer_addr == host ) return c;
      return connection_ptr();
   }

   uint16_t ibc_plugin_impl::to_protocol_version (uint16_t v) {
         return v;
   }
   
   //--------------- handshake_initializer ---------------

   void handshake_initializer::populate( handshake_message &hello) {
      hello.network_version = net_version;
      hello.chain_id = my_impl->chain_id;
      hello.node_id = my_impl->node_id;
      hello.key = my_impl->get_authentication_key();
      hello.time = std::chrono::system_clock::now().time_since_epoch().count();
      hello.token = fc::sha256::hash(hello.time);
      hello.sig = my_impl->sign_compact(hello.key, hello.token);
      // If we couldn't sign, don't send a token.
      if(hello.sig == chain::signature_type())
         hello.token = sha256();
      hello.p2p_address = my_impl->p2p_address + " - " + hello.node_id.str().substr(0,7);
#if defined( __APPLE__ )
      hello.os = "osx";
#elif defined( __linux__ )
      hello.os = "linux";
#elif defined( _MSC_VER )
      hello.os = "win32";
#else
      hello.os = "other";
#endif
      hello.agent = my_impl->user_agent_name;

      controller& cc = my_impl->chain_plug->chain();
      hello.head_id = fc::sha256();
      hello.last_irreversible_block_id = fc::sha256();
      hello.head_num = cc.fork_db_head_block_num();
      hello.last_irreversible_block_num = cc.last_irreversible_block_num();
      if( hello.last_irreversible_block_num ) {
         try {
            hello.last_irreversible_block_id = cc.get_block_id_for_num(hello.last_irreversible_block_num);
         }
         catch( const unknown_block_exception &ex) {
            ilog("caught unkown_block");
            hello.last_irreversible_block_num = 0;
         }
      }
      if( hello.head_num ) {
         try {
            hello.head_id = cc.get_block_id_for_num( hello.head_num );
         }
         catch( const unknown_block_exception &ex) {
            hello.head_num = 0;
         }
      }
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
      auto default_priv_key = private_key_type::regenerate<fc::ecc::private_key_shim>(fc::sha256::hash(std::string("nathan")));

      cfg.add_options()
         ( "ibc-listen-endpoint", bpo::value<string>()->default_value( "0.0.0.0:5678" ), "The actual host:port used to listen for incoming ibc connections.")
         ( "ibc-server-address", bpo::value<string>(), "An externally accessible host:port for identifying this node. Defaults to ibc-listen-endpoint.")
         ( "ibc-peer-address", bpo::value< vector<string> >()->composing(), "The public endpoint of a peer node to connect to. Use multiple ibc-peer-address options as needed to compose a network.")
         ( "ibc-max-nodes-per-host", bpo::value<int>()->default_value(def_max_nodes_per_host), "Maximum number of client nodes from any single IP address")
         ( "ibc-agent-name", bpo::value<string>()->default_value("\"BOS IBC Agent\""), "The name supplied to identify this node amongst the peers.")
         ( "ibc-allowed-connection", bpo::value<vector<string>>()->multitoken()->default_value({"any"}, "any"), "Can be 'any' or 'specified' or 'none'. If 'specified', peer-key must be specified at least once.")
         ( "ibc-peer-key", bpo::value<vector<string>>()->composing()->multitoken(), "Optional public key of peer allowed to connect.  May be used multiple times.")
//         ( "ibc-peer-private-key", bpo::value<vector<string>>()->composing()->multitoken(), "Tuple of [PublicKey, Private key] (may specify multiple times)")
         ( "ibc-peer-private-key", boost::program_options::value<vector<string>>()->composing()->multitoken()->default_value({std::string(default_priv_key.get_public_key()) + "=KEY:" + std::string(default_priv_key)}, std::string(default_priv_key.get_public_key()) + "=KEY:" + std::string(default_priv_key)),
           "Key=Value pairs in the form <public-key>=KEY:<private-key>\n"
           "   <public-key>   \tis a string form of a vaild EOSIO public key\n\n"
           "   <private-key>  \tis a string form of a valid EOSIO private key which maps to the provided public key\n\n")
         ( "ibc-max-clients", bpo::value<int>()->default_value(def_max_clients), "Maximum number of clients from which connections are accepted, use 0 for no limit")
         ( "ibc-connection-cleanup-period", bpo::value<int>()->default_value(def_conn_retry_wait), "number of seconds to wait before cleaning up dead connections")
         ( "ibc-max-cleanup-time-msec", bpo::value<int>()->default_value(10), "max connection cleanup time per cleanup call in millisec")
         ( "ibc-version-match", bpo::value<bool>()->default_value(false), "True to require exact match of ibc plugin version.")
         ( "ibc-sidechain-id", bpo::value<string>(), "the sidechain's chain id")
         ( "ibc-contract", bpo::value<string>(), "the name of this chain's ibc contract")
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

         my->sync_master.reset( new sync_manager );
         my->dispatcher.reset( new dispatch_manager );

         EOS_ASSERT( options.count( "ibc-sidechain-id" ) && options.at("ibc-sidechain-id").as<string>() != string(),
            chain::plugin_config_exception, "ibc-sidechain-id not specified" );
         my->sidechain_id = fc::sha256( options.at( "ibc-sidechain-id" ).as<string>() );
         ilog( "ibc sidechain id is ${id}", ("id",  my->sidechain_id.str()));

         EOS_ASSERT( options.count( "ibc-contract" ) && options.at("ibc-contract").as<string>() != string(),
            chain::plugin_config_exception, "ibc-contract not specified" );
         my->contract.reset( new ibc_contract( eosio::chain::name{ options.at("ibc-contract").as<string>()}));
         ilog( "ibc contract account is ${name}", ("name",  options.at("ibc-contract").as<string>()));

         my->connector_period = std::chrono::seconds( options.at( "ibc-connection-cleanup-period" ).as<int>());
         my->max_cleanup_time_ms = options.at("ibc-max-cleanup-time-msec").as<int>();
         my->max_client_count = options.at( "ibc-max-clients" ).as<int>();
         my->max_nodes_per_host = options.at( "ibc-max-nodes-per-host" ).as<int>();
         my->num_clients = 0;
         my->started_sessions = 0;

         my->resolver = std::make_shared<tcp::resolver>( std::ref( app().get_io_service()));

         if( options.count( "ibc-listen-endpoint" )) {
            my->p2p_address = options.at( "ibc-listen-endpoint" ).as<string>();
            auto host = my->p2p_address.substr( 0, my->p2p_address.find( ':' ));
            auto port = my->p2p_address.substr( host.size() + 1, my->p2p_address.size());
            ilog("ibc listen endpoint is ${h}:${p}",("h", host )("p", port));
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
               if( allowed_remote == "any" )
                  my->allowed_connections |= ibc_plugin_impl::Any;
               else if( allowed_remote == "specified" )
                  my->allowed_connections |= ibc_plugin_impl::Specified;
               else if( allowed_remote == "none" )
                  my->allowed_connections = ibc_plugin_impl::None;
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

//         if( options.count( "ibc-peer-private-key" )) {
//            const std::vector<std::string> key_id_to_pri_pair_strings = options["ibc-peer-private-key"].as<std::vector<std::string>>();
//            for( const std::string& key_id_to_pri_pair_string : key_id_to_pri_pair_strings ) {
//               auto key_id_to_pri_pair = dejsonify<std::pair<chain::public_key_type, std::string>>( key_id_to_pri_pair_string );
//               my->private_keys[key_id_to_pri_pair.first] = private_key_type( key_id_to_pri_pair.second );
//            }
//         }

         if( options.count("ibc-peer-private-key") ) {
            const std::vector<std::string> key_spec_pairs = options["ibc-peer-private-key"].as<std::vector<std::string>>();
            for (const auto& key_spec_pair : key_spec_pairs) {
               try {
                  auto delim = key_spec_pair.find("=");
                  EOS_ASSERT(delim != std::string::npos, plugin_config_exception, "Missing \"=\" in the key spec pair");
                  auto pub_key_str = key_spec_pair.substr(0, delim);
                  auto spec_str = key_spec_pair.substr(delim + 1);

                  auto spec_delim = spec_str.find(":");
                  EOS_ASSERT(spec_delim != std::string::npos, plugin_config_exception, "Missing \":\" in the key spec pair");
                  auto spec_type_str = spec_str.substr(0, spec_delim);
                  auto spec_data = spec_str.substr(spec_delim + 1);

                  auto pubkey = public_key_type(pub_key_str);

                  my->private_keys[pubkey] = private_key_type(spec_data);
               } catch (...) {
                  elog("Malformed ibc-peer-private-key: \"${val}\", ignoring!", ("val", key_spec_pair));
               }
            }
         }

         my->chain_plug = app().find_plugin<chain_plugin>();
         EOS_ASSERT( my->chain_plug, chain::missing_chain_plugin_exception, "" );
         my->chain_id = app().get_plugin<chain_plugin>().get_chain_id();

         fc::rand_pseudo_bytes( my->node_id.data(), my->node_id.data_size());

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

      my->contract->get_basic_info();
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