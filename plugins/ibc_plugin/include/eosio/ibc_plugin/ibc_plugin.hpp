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



   struct section_type {
      uint64_t                first;
      uint64_t                last;
      uint64_t                np_num;
      bool                    valid = false;
      std::vector<name>       producers;
      std::vector<uint32_t>   block_nums;
   };

}}

//FC_REFLECT( eosio::connection_status, (peer)(connecting)(syncing)(last_handshake) )


FC_REFLECT( eosio::ibc::section_type, (first)(last)(np_num)(valid)(producers)(block_nums) )
