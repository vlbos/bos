#include <eosio/chain/block_header_state.hpp>
#include <eosio/chain/exceptions.hpp>
#include <limits>

namespace eosio { namespace chain {

   namespace detail {
      bool is_builtin_activated( const protocol_feature_activation_set_ptr& pfa,
                                 const protocol_feature_set& pfs,
                                 builtin_protocol_feature_t feature_codename )
      {
         auto digest = pfs.get_builtin_digest(feature_codename);
         const auto& protocol_features = pfa->protocol_features;
         return digest && protocol_features.find(*digest) != protocol_features.end();
      }
   }
 bool block_header_state::is_active_producer( account_name n )const {
      return producer_to_last_produced.find(n) != producer_to_last_produced.end();
   }
   producer_key block_header_state::get_scheduled_producer( block_timestamp_type t )const {
      auto index = t.slot % (active_schedule.producers.size() * config::producer_repetitions);
      index /= config::producer_repetitions;
      return active_schedule.producers[index];
   }

   uint32_t block_header_state::calc_dpos_last_irreversible( account_name producer_of_next_block )const {
      vector<uint32_t> blocknums; blocknums.reserve( producer_to_last_implied_irb.size() );
      for( auto& i : producer_to_last_implied_irb ) {
         blocknums.push_back( (i.first == producer_of_next_block) ? dpos_proposed_irreversible_blocknum : i.second);
      }
      /// 2/3 must be greater, so if I go 1/3 into the list sorted from low to high, then 2/3 are greater

      if( blocknums.size() == 0 ) return 0;

      std::size_t index = (blocknums.size()-1) / 3;
      std::nth_element( blocknums.begin(),  blocknums.begin() + index, blocknums.end() );
      return blocknums[ index ];
   }

   pending_block_header_state  block_header_state::next( block_timestamp_type when,
                                                         uint16_t num_prev_blocks_to_confirm ,bool pbft_enabled)const
   {
      pending_block_header_state result;

      if( when != block_timestamp_type() ) {
        EOS_ASSERT( when > header.timestamp, block_validate_exception, "next block must be in the future" );
      } else {
        (when = header.timestamp).slot++;
      }

      auto prokey = get_scheduled_producer(when);

      auto itr = producer_to_last_produced.find( prokey.producer_name );
      if( itr != producer_to_last_produced.end() ) {
        EOS_ASSERT( itr->second < (block_num+1) - num_prev_blocks_to_confirm, producer_double_confirm,
                    "producer ${prod} double-confirming known range",
                    ("prod", prokey.producer_name)("num", block_num+1)
                    ("confirmed", num_prev_blocks_to_confirm)("last_produced", itr->second) );
      }

      result.block_num                                       = block_num + 1;
      result.previous                                        = id;
      result.timestamp                                       = when;
      if (pbft_enabled) {
        result.confirmed = 0;
      } else {
        result.confirmed = num_prev_blocks_to_confirm;
      }
      result.active_schedule_version                         = active_schedule.version;
      result.prev_activated_protocol_features                = activated_protocol_features;

      result.block_signing_key                               = prokey.block_signing_key;
      result.producer                                        = prokey.producer_name;

      result.blockroot_merkle = blockroot_merkle;
      result.blockroot_merkle.append( id );

      /// grow the confirmed count
      static_assert(std::numeric_limits<uint8_t>::max() >= (config::max_producers * 2 / 3) + 1, "8bit confirmations may not be able to hold all of the needed confirmations");

      // This uses the previous block active_schedule because thats the "schedule" that signs and therefore confirms _this_ block
      auto num_active_producers = active_schedule.producers.size();
      uint32_t required_confs = (uint32_t)(num_active_producers * 2 / 3) + 1;


      /// bos
      if (!pbft_enabled) {
        if (confirm_count.size() < config::maximum_tracked_dpos_confirmations) {
          result.confirm_count.reserve(confirm_count.size() + 1);
          result.confirm_count = confirm_count;
          result.confirm_count.resize(confirm_count.size() + 1);
          result.confirm_count.back() = (uint8_t)required_confs;
        } else {
          result.confirm_count.resize(confirm_count.size());
         memcpy( &result.confirm_count[0], &confirm_count[1], confirm_count.size() - 1 );
          result.confirm_count.back() = (uint8_t)required_confs;
        }
      
      auto new_dpos_proposed_irreversible_blocknum = dpos_proposed_irreversible_blocknum;
      int32_t i = (int32_t)(result.confirm_count.size() - 1);
      uint32_t blocks_to_confirm = num_prev_blocks_to_confirm + 1; /// confirm the head block too
      while( i >= 0 && blocks_to_confirm ) {
        --result.confirm_count[i];
        //idump((confirm_count[i]));
        if( result.confirm_count[i] == 0 )
        {
            uint32_t block_num_for_i = result.block_num - (uint32_t)(result.confirm_count.size() - 1 - i);
            new_dpos_proposed_irreversible_blocknum = block_num_for_i;
            //idump((dpos2_lib)(block_num)(dpos_irreversible_blocknum));

            if (i == static_cast<int32_t>(result.confirm_count.size() - 1)) {
               result.confirm_count.resize(0);
            } else {
               memmove( &result.confirm_count[0], &result.confirm_count[i + 1], result.confirm_count.size() - i  - 1);
               result.confirm_count.resize( result.confirm_count.size() - i - 1 );
            }

            break;
        }
        --i;
        --blocks_to_confirm;
      }

	/// bos
    result.pbft_stable_checkpoint_blocknum       = pbft_stable_checkpoint_blocknum;

    
    if (pbft_enabled) {
      result.dpos_irreversible_blocknum = dpos_irreversible_blocknum;
    } else {
      //      result.producer_to_last_implied_irb[prokey.producer_name] =
      //      result.dpos_proposed_irreversible_blocknum;
      //      result.dpos_irreversible_blocknum =
      //      result.calc_dpos_last_irreversible();
      result.dpos_proposed_irreversible_blocknum =          new_dpos_proposed_irreversible_blocknum;
      result.dpos_irreversible_blocknum            = calc_dpos_last_irreversible( prokey.producer_name );
    }

      result.prev_pending_schedule                 = pending_schedule;

      // if( pending_schedule.schedule.producers.size() &&
      //     result.dpos_irreversible_blocknum >= pending_schedule.schedule_lib_num )
      bool should_promote_pending = pending_schedule.schedule.producers.size();
      if ( !pbft_enabled ) {
          should_promote_pending = pending_schedule.schedule.producers.size() &&
          result.dpos_irreversible_blocknum >= pending_schedule.schedule_lib_num ;
      }

      if (should_promote_pending)
      {
         result.active_schedule = pending_schedule.schedule;

         flat_map<account_name,uint32_t> new_producer_to_last_produced;

         for( const auto& pro : result.active_schedule.producers ) {
            if( pro.producer_name == prokey.producer_name ) {
               new_producer_to_last_produced[pro.producer_name] = result.block_num;
            } else {
               auto existing = producer_to_last_produced.find( pro.producer_name );
               if( existing != producer_to_last_produced.end() ) {
                  new_producer_to_last_produced[pro.producer_name] = existing->second;
               } else {
			    //TODO: max of bft and dpos lib
               if (pbft_enabled) {
                   new_producer_to_last_produced[pro.producer_name] = bft_irreversible_blocknum;
               } else {
                  new_producer_to_last_produced[pro.producer_name] = result.dpos_irreversible_blocknum;
				  }
               }
            }
         }
         new_producer_to_last_produced[prokey.producer_name] = result.block_num;

         result.producer_to_last_produced = std::move( new_producer_to_last_produced );

         flat_map<account_name,uint32_t> new_producer_to_last_implied_irb;

         for( const auto& pro : result.active_schedule.producers ) {
            if( pro.producer_name == prokey.producer_name ) {
               new_producer_to_last_implied_irb[pro.producer_name] = dpos_proposed_irreversible_blocknum;
            } else {
               auto existing = producer_to_last_implied_irb.find( pro.producer_name );
               if( existing != producer_to_last_implied_irb.end() ) {
                  new_producer_to_last_implied_irb[pro.producer_name] = existing->second;
               } else {
			   //TODO: max of bft and dpos lib
               if (pbft_enabled) {
                   new_producer_to_last_implied_irb[pro.producer_name] = bft_irreversible_blocknum;
               } else {
                  new_producer_to_last_implied_irb[pro.producer_name] = result.dpos_irreversible_blocknum;
				  }
               }
            }
         }

         result.producer_to_last_implied_irb = std::move( new_producer_to_last_implied_irb );

         result.was_pending_promoted = true;
      } else {
         result.active_schedule                  = active_schedule;
         result.producer_to_last_produced        = producer_to_last_produced;
         result.producer_to_last_produced[prokey.producer_name] = result.block_num;
         result.producer_to_last_implied_irb     = producer_to_last_implied_irb;
         result.producer_to_last_implied_irb[prokey.producer_name] = dpos_proposed_irreversible_blocknum;
      }

      return result;
   }

   signed_block_header pending_block_header_state::make_block_header(
                                                      const checksum256_type& transaction_mroot,
                                                      const checksum256_type& action_mroot,
                                                      const optional<producer_schedule_type>& new_producers,
                                                      vector<digest_type>&& new_protocol_feature_activations,
                                                      const protocol_feature_set& pfs
   )const
   {
      signed_block_header h;

      h.timestamp         = timestamp;
      h.producer          = producer;
      h.confirmed         = confirmed;
      h.previous          = previous;
      h.transaction_mroot = transaction_mroot;
      h.action_mroot      = action_mroot;
      h.schedule_version  = active_schedule_version;
	  h.new_producers     = std::move(new_producers);
///bos
//   result.header.header_extensions  = h.header_extensions;

      if( new_protocol_feature_activations.size() > 0 ) {
         emplace_extension(
               h.header_extensions,
               protocol_feature_activation::extension_id(),
               fc::raw::pack( protocol_feature_activation{ std::move(new_protocol_feature_activations) } )
         );
      }

     

      return h;
   }

   block_header_state pending_block_header_state::_finish_next(
                                 const signed_block_header& h,
                                 const protocol_feature_set& pfs,
                                 const std::function<void( block_timestamp_type,
                                                           const flat_set<digest_type>&,
                                                           const vector<digest_type>& )>& validator,bool pbft_enabled

   )&&
   {
      EOS_ASSERT( h.timestamp == timestamp, block_validate_exception, "timestamp mismatch" );
      EOS_ASSERT( h.previous == previous, unlinkable_block_exception, "previous mismatch" );
      EOS_ASSERT( h.confirmed == confirmed, block_validate_exception, "confirmed mismatch" );
      EOS_ASSERT( h.producer == producer, wrong_producer, "wrong producer specified" );
      EOS_ASSERT( h.schedule_version == active_schedule_version, producer_schedule_exception, "schedule_version in signed block is corrupted" );

      auto exts = h.validate_and_extract_header_extensions();
      if( h.new_producers ) {
         EOS_ASSERT( !was_pending_promoted, producer_schedule_exception, "cannot set pending producer schedule in the same block in which pending was promoted to active" );
         EOS_ASSERT( h.new_producers->version == active_schedule.version + 1, producer_schedule_exception, "wrong producer schedule version specified" );
         EOS_ASSERT( prev_pending_schedule.schedule.producers.size() == 0, producer_schedule_exception,
                    "cannot set new pending producers until last pending is confirmed" );
      }

      protocol_feature_activation_set_ptr new_activated_protocol_features;

      auto exts = h.validate_and_extract_header_extensions();
      { // handle protocol_feature_activation
         if( exts.count(protocol_feature_activation::extension_id() > 0) ) {
            const auto& new_protocol_features = exts.lower_bound(protocol_feature_activation::extension_id())->second.get<protocol_feature_activation>().protocol_features;
            validator( timestamp, prev_activated_protocol_features->protocol_features, new_protocol_features );

            new_activated_protocol_features =   std::make_shared<protocol_feature_activation_set>(
                                                   *prev_activated_protocol_features,
                                                   new_protocol_features
                                                );
         } else {
            new_activated_protocol_features = std::move( prev_activated_protocol_features );
         }
      }

      auto block_number = block_num;

      block_header_state result( std::move( *static_cast<detail::block_header_state_common*>(this) ) );

      result.id      = h.id();
      result.header  = h;

      result.header_exts = std::move(exts);

      if( h.new_producers ) {
         result.pending_schedule.schedule            = *h.new_producers;
         result.pending_schedule.schedule_hash       = digest_type::hash( *h.new_producers );
         result.pending_schedule.schedule_lib_num    = block_number;
      } else {
         if( was_pending_promoted ) {
            result.pending_schedule.schedule.version = prev_pending_schedule.schedule.version;
         } else {
            result.pending_schedule.schedule         = std::move( prev_pending_schedule.schedule );
         }
         result.pending_schedule.schedule_hash       = std::move( prev_pending_schedule.schedule_hash );
         result.pending_schedule.schedule_lib_num    = prev_pending_schedule.schedule_lib_num;
      }

      result.activated_protocol_features = std::move( new_activated_protocol_features );

      return result;
   }

   block_header_state pending_block_header_state::finish_next(
                                 const signed_block_header& h,
                                 const std::function<void( block_timestamp_type,
                                                           const flat_set<digest_type>&,
                                                           const vector<digest_type>& )>& validator,
                                 bool skip_validate_signee,bool pbft_enabled
   )&&
   {
      if( !additional_signatures.empty() ) {
         bool wtmsig_enabled = detail::is_builtin_activated(prev_activated_protocol_features, pfs, builtin_protocol_feature_t::wtmsig_block_signatures);

         EOS_ASSERT(wtmsig_enabled, producer_schedule_exception, "Block contains multiple signatures before WTMsig block signatures are enabled" );
      }

      auto result = std::move(*this)._finish_next( h, pfs, validator );

      if( !additional_signatures.empty() ) {
         result.additional_signatures = std::move(additional_signatures);
      }

      // ASSUMPTION FROM controller_impl::apply_block = all untrusted blocks will have their signatures pre-validated here
      if( !skip_validate_signee ) {
        result.verify_signee( );
      }

      return result;
   }

   block_header_state pending_block_header_state::finish_next(
                                 signed_block_header& h,
                                 const protocol_feature_set& pfs,
                                 const std::function<void( block_timestamp_type,
                                                           const flat_set<digest_type>&,
                                                           const vector<digest_type>& )>& validator,
                                 const signer_callback_type& signer,bool pbft_enabled
   )&&
   {
      auto pfa = prev_activated_protocol_features;

      auto result = std::move(*this)._finish_next( h, pfs, validator );
      result.sign( signer );
      h.producer_signature = result.header.producer_signature;

      if( !result.additional_signatures.empty() ) {
         bool wtmsig_enabled = detail::is_builtin_activated(pfa, pfs, builtin_protocol_feature_t::wtmsig_block_signatures);
         EOS_ASSERT(wtmsig_enabled, producer_schedule_exception, "Block was signed with multiple signatures before WTMsig block signatures are enabled" );
      }

      return result;
   }

   /**
    *  Transitions the current header state into the next header state given the supplied signed block header.
    *
    *  Given a signed block header, generate the expected template based upon the header time,
    *  then validate that the provided header matches the template.
    *
    *  If the header specifies new_producers then apply them accordingly.
    */
   block_header_state block_header_state::next(
                        const signed_block_header& h,
                        vector<signature_type>&& _additional_signatures,
                        const protocol_feature_set& pfs,
                        const std::function<void( block_timestamp_type,
                                                  const flat_set<digest_type>&,
                                                  const vector<digest_type>& )>& validator,
                        bool skip_validate_signee,bool pbft_enabled )const
   {
      return next( h.timestamp, h.confirmed,pbft_enabled).finish_next( h, std::move(_additional_signatures), pfs, validator, skip_validate_signee );
   }

   digest_type   block_header_state::sig_digest()const {
      auto header_bmroot = digest_type::hash( std::make_pair( header.digest(), blockroot_merkle.get_root() ) );
      return digest_type::hash( std::make_pair(header_bmroot, pending_schedule.schedule_hash) );
   }

   void block_header_state::sign( const signer_callback_type& signer ) {
      auto d = sig_digest();
      auto sigs = signer( d );

      EOS_ASSERT(!sigs.empty(), no_block_signatures, "Signer returned no signatures");
      header.producer_signature = sigs.back();
      sigs.pop_back();

      additional_signatures = std::move(sigs);

      verify_signee();
   }

   void block_header_state::verify_signee( )const {
      std::set<public_key_type> keys;
      auto digest = sig_digest();
      keys.emplace(fc::crypto::public_key( header.producer_signature, digest, true ));

      for (const auto& s: additional_signatures) {
         auto res = keys.emplace(s, digest, true);
         EOS_ASSERT(res.second, wrong_signing_key, "block signed by same key twice", ("key", *res.first));
      }

      bool is_satisfied = false;
      size_t relevant_sig_count = 0;

      std::tie(is_satisfied, relevant_sig_count) = producer_authority::keys_satisfy_and_relevant(keys, valid_block_signing_authority);

      EOS_ASSERT(relevant_sig_count == keys.size(), wrong_signing_key,
                 "block signed by unexpected key",
                 ("signing_keys", keys)("authority", valid_block_signing_authority));

      EOS_ASSERT(is_satisfied, wrong_signing_key,
                 "block signatures do not satisfy the block signing authority",
                 ("signing_keys", keys)("authority", valid_block_signing_authority));
   }

   /**
    *  Reference cannot outlive *this. Assumes header_exts is not mutated after instatiation.
    */
   const vector<digest_type>& block_header_state::get_new_protocol_feature_activations()const {
      static const vector<digest_type> no_activations{};

      if( header_exts.count(protocol_feature_activation::extension_id()) == 0 )
         return no_activations;

      return header_exts.lower_bound(protocol_feature_activation::extension_id())->second.get<protocol_feature_activation>().protocol_features;
   }

   block_header_state::block_header_state( legacy::snapshot_block_header_state_v2&& snapshot )
   {
      block_num                             = snapshot.block_num;
      dpos_proposed_irreversible_blocknum   = snapshot.dpos_proposed_irreversible_blocknum;
      dpos_irreversible_blocknum            = snapshot.dpos_irreversible_blocknum;
      active_schedule                       = ( snapshot.active_schedule );
      blockroot_merkle                      = std::move(snapshot.blockroot_merkle);
      producer_to_last_produced             = std::move(snapshot.producer_to_last_produced);
      producer_to_last_implied_irb          = std::move(snapshot.producer_to_last_implied_irb);
      // valid_block_signing_authority         = block_signing_authority_v0{ 1, {{std::move(snapshot.block_signing_key), 1}} };
      confirm_count                         = std::move(snapshot.confirm_count);
      id                                    = std::move(snapshot.id);
      header                                = std::move(snapshot.header);
      pending_schedule.schedule_lib_num     = snapshot.pending_schedule.schedule_lib_num;
      pending_schedule.schedule_hash        = std::move(snapshot.pending_schedule.schedule_hash);
      pending_schedule.schedule             = ( snapshot.pending_schedule.schedule );
      activated_protocol_features           = std::move(snapshot.activated_protocol_features);
   }


} } /// namespace eosio::chain
