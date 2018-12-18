/**
 *  @file
 *  @copyright defined in bos/LICENSE.txt
 */
#pragma once
#include <eosio/chain/block.hpp>
#include <eosio/chain/types.hpp>
#include <chrono>

namespace eosio {
   namespace ibc {
      using namespace chain;
      using namespace fc;

      static_assert(sizeof(std::chrono::system_clock::duration::rep) >= 8, "system_clock is expected to be at least 64 bits");
      typedef std::chrono::system_clock::duration::rep tstamp;

      struct handshake_message {
         uint16_t                   network_version = 0; ///< incremental value above a computed base
         fc::sha256                 chain_id; ///< used to identify chain
         fc::sha256                 node_id; ///< used to identify peers and prevent self-connect
         chain::public_key_type     key; ///< authentication key; may be a producer or peer key, or empty
         tstamp                     time;
         fc::sha256                 token; ///< digest of time to prove we own the private key of the key above
         chain::signature_type      sig; ///< signature for the digest
         string                     p2p_address;
         uint32_t                   last_irreversible_block_num = 0;
         block_id_type              last_irreversible_block_id;
         uint32_t                   head_num = 0;
         block_id_type              head_id;
         string                     os;
         string                     agent;
         int16_t                    generation;
      };

      enum go_away_reason {
         no_reason, ///< no reason to go away
         self, ///< the connection is to itself
         duplicate, ///< the connection is redundant
         wrong_chain, ///< the peer's chain id doesn't match with setting
         same_chain, ///< the connection is to same chain
         wrong_version, ///< the peer's network version doesn't match
         forked, ///< the peer forked in it's own chain
         unlinkable, ///< the peer sent a block we couldn't use
         bad_transaction, ///< the peer sent a transaction that failed verification
         validation, ///< the peer sent a block that failed validation
         benign_other, ///< reasons such as a timeout. not fatal but warrant resetting
         fatal_other, ///< a catch-all for errors we don't have discriminated
         authentication ///< peer failed authenicatio
      };

      constexpr auto reason_str( go_away_reason rsn ) {
         switch (rsn ) {
            case no_reason : return "no reason";
            case self : return "self connect";
            case duplicate : return "duplicate";
            case wrong_chain : return "wrong chain";
            case same_chain : return "same chain";
            case wrong_version : return "wrong version";
            case forked : return "chain is forked";
            case unlinkable : return "unlinkable block received";
            case bad_transaction : return "bad transaction";
            case validation : return "invalid block";
            case authentication : return "authentication failure";
            case fatal_other : return "some other failure";
            case benign_other : return "some other non-fatal condition";
            default : return "some crazy reason";
         }
      }

      struct go_away_message {
         go_away_message (go_away_reason r = no_reason) : reason(r), node_id() {}
         go_away_reason reason;
         fc::sha256 node_id; ///< for duplicate notification
      };

      struct time_message {
         tstamp  org;       //!< origin timestamp
         tstamp  rec;       //!< receive timestamp
         tstamp  xmt;       //!< transmit timestamp
         mutable tstamp  dst;       //!< destination timestamp
      };

      /**
       * Abbreviated vocabulary description:
       * "lwc" means eosio light weight client
       * "ls" or "lwcls" means eosio light weight client last section in ibc contract
       */

      enum lwc_contract_state {
         none, ///< ibc contract has not deployed
         deployed, ///< ibc constract has deployed, but not initialized
         working, ///< ibc constract has been initialized and in working state
         stoped ///< ibc contract stoped for some reason
      };

      /**
       * this hearbeat message should broadcast with time_message
       * and when the lwcls has any update broadcast this too.
       */
      struct lwc_heartbeat_message {
         lwc_contract_state state;
         uint32_t       ls_first_num;
         uint32_t       ls_last_num;
         uint32_t       ls_lib_num;
         block_id_type  ls_first_id;
         block_id_type  ls_last_id;
         block_id_type  ls_lib_id;
         bool           ls_valid;
      };

      /**
       * send when sync_manager has no information of light weight client or ids from
       * "lwc_heartbeat_message" does not match with local blockchain.
       * peer chain should feed back "lwcls_detail_message"
       */
      struct request_lwcls_message {
         uint32_t num;  //!< get the last num block ids in the last section of the lwc, 0 means all ids of last section
      };

      struct lwcls_detail_message {
         uint32_t       first_num;
         uint32_t       last_num;
         uint32_t       lib_num;
         block_id_type  first_id;
         block_id_type  last_id;
         block_id_type  lib_id;
         bool           valid;
         std::vector<block_id_type> ids;
      };

      /**
       * send when last section's first blcok number is 0
       */
      struct lwc_init_message {
         signed_block_header     header;
         producer_schedule_type  active_schedule;
         incremental_merkle      blockroot_merkle;
      };

      struct lwc_section_data {
         std::vector<signed_block_header>    headers;
         incremental_merkle                  blockroot_merkle;
      };

      struct lwc_ibctrx_data {
         block_id_type              block_id;
         transaction_receipt        trx;
         std::vector<digest_type>   merkle_path;
      };

      /**
       * when a new version producer_schedule update completed, send the last block id before the update process.
       * when a ibc trx irreversible, send the block id which block contains the transaction.
       * when there is no ibc trx within a long time (such as one hour), random send a recent irreversible block's id.
       *
       * when recieve this message the peer chain's ibc plugin will send "lwc_request_message"
       */
      struct notice_lwc_block_message {
         uint32_t       num;
         block_id_type  id;
      };

      struct lwc_request_message {
         uint32_t start_block_num;
         uint32_t end_block_num;
      };

      using ibc_message = static_variant< handshake_message,
                                          go_away_message,
                                          time_message,
                                          lwc_heartbeat_message,
                                          request_lwcls_message,
                                          lwcls_detail_message,
                                          lwc_init_message,
                                          lwc_section_data,
                                          lwc_ibctrx_data,
                                          notice_lwc_block_message,
                                          lwc_request_message >;

   } // namespace ibc
} // namespace eosio


FC_REFLECT( eosio::ibc::handshake_message,
            (network_version)(chain_id)(node_id)(key)
            (time)(token)(sig)(p2p_address)
            (last_irreversible_block_num)(last_irreversible_block_id)
            (head_num)(head_id)
            (os)(agent)(generation) )
FC_REFLECT( eosio::ibc::go_away_message, (reason)(node_id) )
FC_REFLECT( eosio::ibc::time_message, (org)(rec)(xmt)(dst) )

FC_REFLECT( eosio::ibc::lwc_heartbeat_message, (ls_first_num)(ls_last_num)(ls_lib_num)(ls_first_id)(ls_last_id)(ls_lib_id)(ls_valid) )
FC_REFLECT( eosio::ibc::request_lwcls_message, (num) )
FC_REFLECT( eosio::ibc::lwcls_detail_message, (first_num)(last_num)(lib_num)(first_id)(last_id)(lib_id)(valid)(ids) )
FC_REFLECT( eosio::ibc::lwc_init_message, (header)(active_schedule)(blockroot_merkle)  )
FC_REFLECT( eosio::ibc::lwc_section_data, (headers)(blockroot_merkle)  )
FC_REFLECT( eosio::ibc::lwc_ibctrx_data, (block_id)(trx)(merkle_path)  )
FC_REFLECT( eosio::ibc::notice_lwc_block_message, (num)(id) )
FC_REFLECT( eosio::ibc::lwc_request_message, (start_block_num)(end_block_num) )
