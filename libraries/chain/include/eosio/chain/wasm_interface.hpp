#pragma once
#include <eosio/chain/types.hpp>
#include <eosio/chain/exceptions.hpp>
#if defined(EOSIO_EOS_VM_RUNTIME_ENABLED) || defined(EOSIO_EOS_VM_JIT_RUNTIME_ENABLED)
#include <eosio/vm/allocator.hpp>
#endif
#include "Runtime/Linker.h"
#include "Runtime/Runtime.h"

namespace eosio { namespace chain {

   class apply_context;
   class wasm_runtime_interface;
   class controller;
   namespace eosvmoc { struct config; }

   struct wasm_exit {
      int32_t code = 0;
   };

   namespace webassembly { namespace common {
      class intrinsics_accessor;

      struct root_resolver : Runtime::Resolver {
         //when validating is true; only allow "env" imports. Otherwise allow any imports. This resolver is used
         //in two cases: once by the generic validating code where we only want "env" to pass; and then second in the
         //wavm runtime where we need to allow linkage to injected functions
         root_resolver(bool validating = false) : validating(validating) {}
         bool validating;

         bool resolve(const string& mod_name,
                      const string& export_name,
                      IR::ObjectType type,
                      Runtime::ObjectInstance*& out) override {
      try {
         //protect access to "private" injected functions; so for now just simply allow "env" since injected functions
         //  are in a different module
         if(validating && mod_name != "env")
            EOS_ASSERT( false, wasm_exception, "importing from module that is not 'env': ${module}.${export}", ("module",mod_name)("export",export_name) );

         // Try to resolve an intrinsic first.
         if(Runtime::IntrinsicResolver::singleton.resolve(mod_name,export_name,type, out)) {
            return true;
         }

         EOS_ASSERT( false, wasm_exception, "${module}.${export} unresolveable", ("module",mod_name)("export",export_name) );
         return false;
      } FC_CAPTURE_AND_RETHROW( (mod_name)(export_name) ) }
      };
   } }

   /**
    * @class wasm_interface
    *
    */
   class wasm_interface {
      public:
         enum class vm_type {
            wavm,
            wabt,
            eos_vm,
            eos_vm_jit,
            eos_vm_oc
         };

         wasm_interface(vm_type vm, bool eosvmoc_tierup, const chainbase::database& d, const boost::filesystem::path data_dir, const eosvmoc::config& eosvmoc_config);
         ~wasm_interface();

         //validates code -- does a WASM validation pass and checks the wasm against EOSIO specific constraints
         static void validate(const controller& control, const bytes& code);
         //indicate that a particular code probably won't be used after given block_num
         void code_block_num_last_used(const digest_type& code_hash, const uint8_t& vm_type, const uint8_t& vm_version, const uint32_t& block_num);

         //Calls apply or error on a given code
         void apply(const digest_type& code_hash, const uint8_t& vm_type, const uint8_t& vm_version, apply_context& context);

         //Immediately exits currently running wasm. UB is called when no wasm running
         void exit();

      private:
         unique_ptr<struct wasm_interface_impl> my;
         friend class eosio::chain::webassembly::common::intrinsics_accessor;
   };

} } // eosio::chain

namespace eosio{ namespace chain {
   std::istream& operator>>(std::istream& in, wasm_interface::vm_type& runtime);
}}

FC_REFLECT_ENUM( eosio::chain::wasm_interface::vm_type, (wavm)(wabt)(eos_vm)(eos_vm_jit)(eos_vm_oc) )
