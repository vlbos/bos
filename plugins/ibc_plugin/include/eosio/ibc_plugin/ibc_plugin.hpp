/**
 *  @file
 *  @copyright defined in bos/LICENSE.txt
 */
#pragma once

#include <appbase/application.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/ibc_plugin/protocol.hpp>

namespace eosio { namespace ibc {
   using namespace appbase;

   struct connection_status {
      string            peer;
      bool              connecting = false;
      bool              syncing    = false;
      handshake_message last_handshake;
   };

   class ibc_plugin : public appbase::plugin<ibc_plugin>
   {
      public:
        ibc_plugin();
        virtual ~ibc_plugin();

        APPBASE_PLUGIN_REQUIRES((chain_plugin))
        virtual void set_program_options(options_description& cli, options_description& cfg) override;

        void plugin_initialize(const variables_map& options);
        void plugin_startup();
        void plugin_shutdown();

        string                       connect( const string& endpoint );
        string                       disconnect( const string& endpoint );
        optional<connection_status>  status( const string& endpoint )const;
        vector<connection_status>    connections()const;

        size_t num_peers() const;
      private:
        std::unique_ptr<class ibc_plugin_impl> my;
   };



   // ---- ibc contract table structs ----

   struct global_state {
      uint32_t    lib_depth;
   };

   struct section_type {
      uint64_t                first;
      uint64_t                last;
      uint64_t                np_num;
      bool                    valid = false;
      std::vector<name>       producers;
      std::vector<uint32_t>   block_nums;
   };

   struct block_header_state_type {
      block_header_state_type():block_num(0),block_id(),header(),active_schedule_id(0),
      pending_schedule_id(0),blockroot_merkle(),block_signing_key(){}
      uint64_t                   block_num;
      block_id_type              block_id;
      signed_block_header        header;
      uint32_t                   active_schedule_id;
      uint32_t                   pending_schedule_id;
      incremental_merkle         blockroot_merkle;
      public_key_type            block_signing_key;
   };

   struct ibctrx_info {
      uint64_t             id;
      uint32_t             block_time_slot;
      transaction_id_type  trx_id;
      name                 from;
      name                 to;
      asset                quantity;
      string               memo;
      transaction_id_type  dest_trx_id;
      uint64_t             state;
   };

   struct remote_local_trx_info {
      uint64_t             id;
      transaction_id_type  r_trx_id;
      name                 r_from;
      name                 r_to;
      asset                r_quantity;
      string               r_memo;
      transaction_id_type  l_trx_id;
      name                 l_from;
      name                 l_to;
      asset                l_quantity;
      string               l_memo;
   };

   //  ---- ibc contract push action related structs ----
   struct new_section_params {
      std::vector<signed_block_header>  headers;
      incremental_merkle                blockroot_merkle;
   };

}}

//FC_REFLECT( eosio::connection_status, (peer)(connecting)(syncing)(last_handshake) )

FC_REFLECT( eosio::ibc::global_state, (lib_depth) )
FC_REFLECT( eosio::ibc::section_type, (first)(last)(np_num)(valid)(producers)(block_nums) )
FC_REFLECT( eosio::ibc::new_section_params, (headers)(blockroot_merkle) )
FC_REFLECT( eosio::ibc::block_header_state_type, (block_num)(block_id)(header)(active_schedule_id)(pending_schedule_id)(blockroot_merkle)(block_signing_key) )
FC_REFLECT( eosio::ibc::ibctrx_info, (id)(block_time_slot)(trx_id)(from)(to)(quantity)(memo)(dest_trx_id)(state) )
FC_REFLECT( eosio::ibc::remote_local_trx_info, (id)(r_trx_id)(r_from)(r_to)(r_quantity)(r_memo)(l_trx_id)(l_from)(l_to)(l_quantity)(l_memo) )





