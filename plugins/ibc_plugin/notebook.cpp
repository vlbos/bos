


if ( msg.headers.front().block_num() > obj.last ){ // new section and push headers
//         new_section_params par;
//         par.headers = msg.headers;
//         par.blockroot_merkle = msg.blockroot_merkle;
////         chain_contract->newsection( par );
//         return;
//      }




// find the first block number, which id is same in msg and lwc chaindb.
uint32_t check_num_first = std::min( uint32_t(obj.last), msg.headers.rbegin()->block_num() );
uint32_t check_num_last = std::max( uint32_t(obj.valid ? obj.last - chain_contract->lwc_lib_depth : obj.first)
      , msg.headers.front().block_num() );
uint32_t identical_num = 0;
uint32_t check_num = check_num_first;
while ( check_num >= check_num_last ){
auto id_from_msg = msg.headers[ check_num - msg.headers.front().block_num()].id();
auto id_from_lwc = chain_contract->get_chaindb_tb_block_id_by_block_num( check_num );
if ( id_from_lwc != block_id_type() && id_from_msg == id_from_lwc ){
identical_num = check_num;
break;
}
--check_num;
}
if ( identical_num == 0 ){
if ( check_num == obj.first ){
// delete lwcls
}
return;
}

// construct and push headers
std::vector<signed_block_header> headers;

auto first_itr = msg.headers.begin() + ( identical_num - msg.headers.front().block_num() );
auto last_itr = msg.headers.end();
if ( msg.headers.rbegin()->block_num() - identical_num > 50 ){ // max block header per time
last_itr = first_itr + 50;
}
//      chain_contract->addheaders( std::vector<signed_block_header>(first_itr, last_itr) );