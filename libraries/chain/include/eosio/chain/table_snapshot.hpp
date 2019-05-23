/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#pragma once
#include <appbase/application.hpp>
#include <eosio/chain/asset.hpp>
#include <eosio/chain/authority.hpp>
#include <eosio/chain/account_object.hpp>
#include <eosio/chain/block.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/contract_table_objects.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/chain/transaction.hpp>
#include <eosio/chain/abi_serializer.hpp>
// #include <eosio/chain/plugin_interface.hpp>
#include <eosio/chain/types.hpp>

#include <boost/container/flat_set.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <fc/static_variant.hpp>

namespace fc { class variant; }

namespace eosio {
   using chain::controller;
   using std::unique_ptr;
   using std::pair;
   using namespace appbase;
   using chain::name;
   using chain::uint128_t;
   using chain::public_key_type;
   using chain::transaction;
   using chain::transaction_id_type;
   using fc::optional;
   using boost::container::flat_set;
   using chain::asset;
   using chain::symbol;
   using chain::authority;
   using chain::account_name;
   using chain::action_name;
   using chain::abi_def;
   using chain::abi_serializer;

namespace table_snapshot_apis {


// see specializations for uint64_t and double in source file
template<typename Type>
Type convert_to_type(const string& str, const string& desc) {
   try {
      return fc::variant(str).as<Type>();
   } FC_RETHROW_EXCEPTIONS(warn, "Could not convert ${desc} string '${str}' to key type.", ("desc", desc)("str",str) )
}

template<>
uint64_t convert_to_type(const string& str, const string& desc);

template<>
double convert_to_type(const string& str, const string& desc);

class table_snapshot {
   const controller& db;
   const fc::microseconds abi_serializer_max_time;
   bool  shorten_abi_errors = true;

public:
   static const string KEYi64;

   table_snapshot(const controller& db, const fc::microseconds& abi_serializer_max_time)
      : db(db), abi_serializer_max_time(abi_serializer_max_time) {}

   void validate() const {}

   void set_shorten_abi_errors( bool f ) { shorten_abi_errors = f; }


   struct get_table_rows_params {
      bool        json = false;
      name        code;
      string      scope;
      name        table;
      string      table_key;
      string      lower_bound;
      string      upper_bound;
      uint32_t    limit = 10;
      string      key_type;  // type of key specified by index_position
      string      index_position; // 1 - primary (first), 2 - secondary index (in order defined by multi_index), 3 - third index, etc
      string      encode_type{"dec"}; //dec, hex , default=dec
      optional<bool>  reverse;
      optional<bool>  show_payer; // show RAM pyer
    };

   struct get_table_rows_result {
      vector<fc::variant> rows; ///< one row per item, either encoded as hex String or JSON object
      bool                more = false; ///< true if last element in data is not the end and sizeof data() < limit
   };

   get_table_rows_result get_table_rows( const get_table_rows_params& params )const;

   

   static void copy_inline_row(const chain::key_value_object& obj, vector<char>& data) {
      data.resize( obj.value.size() );
      memcpy( data.data(), obj.value.data(), obj.value.size() );
   }


   static uint64_t get_table_index_name(const table_snapshot::get_table_rows_params& p, bool& primary);

   

   template <typename IndexType>
   table_snapshot::get_table_rows_result 
   get_table_rows_ex( const table_snapshot::get_table_rows_params& p, const abi_def& abi )const {
      table_snapshot::get_table_rows_result result;
      const auto& d = db.db();

      uint64_t scope = convert_to_type<uint64_t>(p.scope, "scope");

      abi_serializer abis;
      abis.set_abi(abi, abi_serializer_max_time);
      const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(p.code, scope, p.table));
      if( t_id != nullptr ) {
         const auto& idx = d.get_index<IndexType, chain::by_scope_primary>();
         auto lower_bound_lookup_tuple = std::make_tuple( t_id->id, std::numeric_limits<uint64_t>::lowest() );
         auto upper_bound_lookup_tuple = std::make_tuple( t_id->id, std::numeric_limits<uint64_t>::max() );

         // if( p.lower_bound.size() ) {
         //    if( p.key_type == "name" ) {
         //       name s(p.lower_bound);
         //       std::get<1>(lower_bound_lookup_tuple) = s.value;
         //    } else {
         //       auto lv = convert_to_type<typename IndexType::value_type::key_type>( p.lower_bound, "lower_bound" );
         //       std::get<1>(lower_bound_lookup_tuple) = lv;
         //    }
         // }

         // if( p.upper_bound.size() ) {
         //    if( p.key_type == "name" ) {
         //       name s(p.upper_bound);
         //       std::get<1>(upper_bound_lookup_tuple) = s.value;
         //    } else {
         //       auto uv = convert_to_type<typename IndexType::value_type::key_type>( p.upper_bound, "upper_bound" );
         //       std::get<1>(upper_bound_lookup_tuple) = uv;
         //    }
         // }

         if( upper_bound_lookup_tuple < lower_bound_lookup_tuple  )
            return result;

         auto walk_table_row_range = [&]( auto itr, auto end_itr ) {
            auto cur_time = fc::time_point::now();
            auto end_time = cur_time + fc::microseconds(1000 * uint64_t(3600'000)); /// 1h max time
            vector<char> data;
            for( unsigned int count = 0; cur_time <= end_time && count < p.limit && itr != end_itr; ++count, ++itr, cur_time = fc::time_point::now() ) {

               copy_inline_row(*itr, data);

               fc::variant data_var;
               if( p.json ) {
                  data_var = abis.binary_to_variant( abis.get_table_type(p.table), data, abi_serializer_max_time, shorten_abi_errors );
               } else {
                  data_var = fc::variant( data );
               }

               if( p.show_payer && *p.show_payer ) {
                  result.rows.emplace_back( fc::mutable_variant_object("data", std::move(data_var))("payer", itr->payer) );
               } else {
                  result.rows.emplace_back( std::move(data_var) );
               }
            }
            if( itr != end_itr ) {
               result.more = true;
            }
         };

         auto lower = idx.lower_bound( lower_bound_lookup_tuple );
         auto upper = idx.upper_bound( upper_bound_lookup_tuple );
         if( p.reverse && *p.reverse ) {
            walk_table_row_range( boost::make_reverse_iterator(upper), boost::make_reverse_iterator(lower) );
         } else {
            walk_table_row_range( lower, upper );
         }
      }
      return result;
   }

 
};


} // namespace table_snapshot_apis



}



FC_REFLECT( eosio::table_snapshot_apis::table_snapshot::get_table_rows_params, (json)(code)(scope)(table)(table_key)(lower_bound)(upper_bound)(limit)(key_type)(index_position)(encode_type)(reverse)(show_payer) )
FC_REFLECT( eosio::table_snapshot_apis::table_snapshot::get_table_rows_result, (rows)(more) );

