# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: management.proto
# Protobuf Python Version: 5.29.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    0,
    '',
    'management.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10management.proto\x12\nmanagement\"\x10\n\x0eGetInfoRequest\"/\n\x0fMintInfoContact\x12\x0e\n\x06method\x18\x01 \x01(\t\x12\x0c\n\x04info\x18\x02 \x01(\t\"\x87\x03\n\x0fGetInfoResponse\x12\x11\n\x04name\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x13\n\x06pubkey\x18\x02 \x01(\tH\x01\x88\x01\x01\x12\x14\n\x07version\x18\x03 \x01(\tH\x02\x88\x01\x01\x12\x18\n\x0b\x64\x65scription\x18\x04 \x01(\tH\x03\x88\x01\x01\x12\x1d\n\x10\x64\x65scription_long\x18\x05 \x01(\tH\x04\x88\x01\x01\x12,\n\x07\x63ontact\x18\x06 \x03(\x0b\x32\x1b.management.MintInfoContact\x12\x11\n\x04motd\x18\x07 \x01(\tH\x05\x88\x01\x01\x12\x15\n\x08icon_url\x18\x08 \x01(\tH\x06\x88\x01\x01\x12\x0c\n\x04urls\x18\t \x03(\t\x12\x11\n\x04time\x18\n \x01(\x03H\x07\x88\x01\x01\x12\x14\n\x07tos_url\x18\x0b \x01(\tH\x08\x88\x01\x01\x42\x07\n\x05_nameB\t\n\x07_pubkeyB\n\n\x08_versionB\x0e\n\x0c_descriptionB\x13\n\x11_description_longB\x07\n\x05_motdB\x0b\n\t_icon_urlB\x07\n\x05_timeB\n\n\x08_tos_url\"\x10\n\x0eUpdateResponse\"!\n\x11UpdateMotdRequest\x12\x0c\n\x04motd\x18\x01 \x01(\t\"/\n\x18UpdateDescriptionRequest\x12\x13\n\x0b\x64\x65scription\x18\x01 \x01(\t\"(\n\x14UpdateIconUrlRequest\x12\x10\n\x08icon_url\x18\x01 \x01(\t\"!\n\x11UpdateNameRequest\x12\x0c\n\x04name\x18\x01 \x01(\t\"\x1f\n\x10UpdateUrlRequest\x12\x0b\n\x03url\x18\x01 \x01(\t\"4\n\x14UpdateContactRequest\x12\x0e\n\x06method\x18\x01 \x01(\t\x12\x0c\n\x04info\x18\x02 \x01(\t\"\xb4\x01\n\x12UpdateNut04Request\x12\x0c\n\x04unit\x18\x01 \x01(\t\x12\x0e\n\x06method\x18\x02 \x01(\t\x12\x15\n\x08\x64isabled\x18\x03 \x01(\x08H\x00\x88\x01\x01\x12\x10\n\x03min\x18\x04 \x01(\x04H\x01\x88\x01\x01\x12\x10\n\x03max\x18\x05 \x01(\x04H\x02\x88\x01\x01\x12\x18\n\x0b\x64\x65scription\x18\x06 \x01(\x08H\x03\x88\x01\x01\x42\x0b\n\t_disabledB\x06\n\x04_minB\x06\n\x04_maxB\x0e\n\x0c_description\"\x8a\x01\n\x12UpdateNut05Request\x12\x0c\n\x04unit\x18\x01 \x01(\t\x12\x0e\n\x06method\x18\x02 \x01(\t\x12\x15\n\x08\x64isabled\x18\x03 \x01(\x08H\x00\x88\x01\x01\x12\x10\n\x03min\x18\x04 \x01(\x04H\x01\x88\x01\x01\x12\x10\n\x03max\x18\x05 \x01(\x04H\x02\x88\x01\x01\x42\x0b\n\t_disabledB\x06\n\x04_minB\x06\n\x04_max\"1\n\x15UpdateQuoteTtlRequest\x12\x10\n\x03ttl\x18\x01 \x01(\x04H\x00\x88\x01\x01\x42\x06\n\x04_ttl\"\x9f\x02\n\nNut04Quote\x12\r\n\x05quote\x18\x01 \x01(\t\x12\x0e\n\x06method\x18\x02 \x01(\t\x12\x0f\n\x07request\x18\x03 \x01(\t\x12\x13\n\x0b\x63hecking_id\x18\x04 \x01(\t\x12\x0c\n\x04unit\x18\x05 \x01(\t\x12\x0e\n\x06\x61mount\x18\x06 \x01(\x04\x12\x12\n\x05state\x18\x07 \x01(\tH\x00\x88\x01\x01\x12\x19\n\x0c\x63reated_time\x18\x08 \x01(\x03H\x01\x88\x01\x01\x12\x16\n\tpaid_time\x18\t \x01(\x03H\x02\x88\x01\x01\x12\x13\n\x06\x65xpiry\x18\n \x01(\x03H\x03\x88\x01\x01\x12\x13\n\x06pubkey\x18\r \x01(\tH\x04\x88\x01\x01\x42\x08\n\x06_stateB\x0f\n\r_created_timeB\x0c\n\n_paid_timeB\t\n\x07_expiryB\t\n\x07_pubkey\"Z\n\x0e\x42lindedMessage\x12\x0e\n\x06\x61mount\x18\x01 \x01(\x05\x12\n\n\x02id\x18\x02 \x01(\t\x12\n\n\x02\x42_\x18\x03 \x01(\t\x12\x14\n\x07witness\x18\x04 \x01(\tH\x00\x88\x01\x01\x42\n\n\x08_witness\"\x1c\n\x04\x44LEQ\x12\t\n\x01\x65\x18\x01 \x01(\t\x12\t\n\x01s\x18\x02 \x01(\t\"h\n\x10\x42lindedSignature\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0e\n\x06\x61mount\x18\x02 \x01(\x05\x12\n\n\x02\x43_\x18\x03 \x01(\t\x12#\n\x04\x64leq\x18\x04 \x01(\x0b\x32\x10.management.DLEQH\x00\x88\x01\x01\x42\x07\n\x05_dleq\"\xa6\x03\n\nNut05Quote\x12\r\n\x05quote\x18\x01 \x01(\t\x12\x0e\n\x06method\x18\x02 \x01(\t\x12\x0f\n\x07request\x18\x03 \x01(\t\x12\x13\n\x0b\x63hecking_id\x18\x04 \x01(\t\x12\x0c\n\x04unit\x18\x05 \x01(\t\x12\x0e\n\x06\x61mount\x18\x06 \x01(\x05\x12\x13\n\x0b\x66\x65\x65_reserve\x18\x07 \x01(\x05\x12\r\n\x05state\x18\x08 \x01(\t\x12\x19\n\x0c\x63reated_time\x18\t \x01(\x03H\x00\x88\x01\x01\x12\x16\n\tpaid_time\x18\n \x01(\x03H\x01\x88\x01\x01\x12\x10\n\x08\x66\x65\x65_paid\x18\x0b \x01(\x05\x12\x1d\n\x10payment_preimage\x18\x0c \x01(\tH\x02\x88\x01\x01\x12\x13\n\x06\x65xpiry\x18\r \x01(\x03H\x03\x88\x01\x01\x12+\n\x07outputs\x18\x0e \x03(\x0b\x32\x1a.management.BlindedMessage\x12,\n\x06\x63hange\x18\x0f \x03(\x0b\x32\x1c.management.BlindedSignatureB\x0f\n\r_created_timeB\x0c\n\n_paid_timeB\x13\n\x11_payment_preimageB\t\n\x07_expiry\"(\n\x14GetNut04QuoteRequest\x12\x10\n\x08quote_id\x18\x01 \x01(\t\">\n\x15GetNut04QuoteResponse\x12%\n\x05quote\x18\x01 \x01(\x0b\x32\x16.management.Nut04Quote\"(\n\x14GetNut05QuoteRequest\x12\x10\n\x08quote_id\x18\x01 \x01(\t\">\n\x15GetNut05QuoteResponse\x12%\n\x05quote\x18\x01 \x01(\x0b\x32\x16.management.Nut05Quote\"5\n\x12UpdateQuoteRequest\x12\x10\n\x08quote_id\x18\x01 \x01(\t\x12\r\n\x05state\x18\x02 \x01(\t\"{\n\x17RotateNextKeysetRequest\x12\x0c\n\x04unit\x18\x01 \x01(\t\x12\x16\n\tmax_order\x18\x02 \x01(\rH\x00\x88\x01\x01\x12\x1a\n\rinput_fee_ppk\x18\x03 \x01(\x04H\x01\x88\x01\x01\x42\x0c\n\n_max_orderB\x10\n\x0e_input_fee_ppk\"^\n\x18RotateNextKeysetResponse\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0c\n\x04unit\x18\x02 \x01(\t\x12\x11\n\tmax_order\x18\x03 \x01(\r\x12\x15\n\rinput_fee_ppk\x18\x04 \x01(\x04\"w\n\x19UpdateLightningFeeRequest\x12\x18\n\x0b\x66\x65\x65_percent\x18\x01 \x01(\x01H\x00\x88\x01\x01\x12\x1c\n\x0f\x66\x65\x65_min_reserve\x18\x02 \x01(\x04H\x01\x88\x01\x01\x42\x0e\n\x0c_fee_percentB\x12\n\x10_fee_min_reserve\"\x9f\x01\n\x17UpdateAuthLimitsRequest\x12\'\n\x1a\x61uth_rate_limit_per_minute\x18\x01 \x01(\x04H\x00\x88\x01\x01\x12\"\n\x15\x61uth_max_blind_tokens\x18\x02 \x01(\x04H\x01\x88\x01\x01\x42\x1d\n\x1b_auth_rate_limit_per_minuteB\x18\n\x16_auth_max_blind_tokens2\xf0\x0c\n\x04Mint\x12\x44\n\x07GetInfo\x12\x1a.management.GetInfoRequest\x1a\x1b.management.GetInfoResponse\"\x00\x12I\n\nUpdateMotd\x12\x1d.management.UpdateMotdRequest\x1a\x1a.management.UpdateResponse\"\x00\x12\\\n\x16UpdateShortDescription\x12$.management.UpdateDescriptionRequest\x1a\x1a.management.UpdateResponse\"\x00\x12[\n\x15UpdateLongDescription\x12$.management.UpdateDescriptionRequest\x1a\x1a.management.UpdateResponse\"\x00\x12O\n\rUpdateIconUrl\x12 .management.UpdateIconUrlRequest\x1a\x1a.management.UpdateResponse\"\x00\x12I\n\nUpdateName\x12\x1d.management.UpdateNameRequest\x1a\x1a.management.UpdateResponse\"\x00\x12\x44\n\x06\x41\x64\x64Url\x12\x1c.management.UpdateUrlRequest\x1a\x1a.management.UpdateResponse\"\x00\x12G\n\tRemoveUrl\x12\x1c.management.UpdateUrlRequest\x1a\x1a.management.UpdateResponse\"\x00\x12L\n\nAddContact\x12 .management.UpdateContactRequest\x1a\x1a.management.UpdateResponse\"\x00\x12O\n\rRemoveContact\x12 .management.UpdateContactRequest\x1a\x1a.management.UpdateResponse\"\x00\x12V\n\rGetNut04Quote\x12 .management.GetNut04QuoteRequest\x1a!.management.GetNut04QuoteResponse\"\x00\x12V\n\rGetNut05Quote\x12 .management.GetNut05QuoteRequest\x1a!.management.GetNut05QuoteResponse\"\x00\x12K\n\x0bUpdateNut04\x12\x1e.management.UpdateNut04Request\x1a\x1a.management.UpdateResponse\"\x00\x12K\n\x0bUpdateNut05\x12\x1e.management.UpdateNut05Request\x1a\x1a.management.UpdateResponse\"\x00\x12Q\n\x0eUpdateQuoteTtl\x12!.management.UpdateQuoteTtlRequest\x1a\x1a.management.UpdateResponse\"\x00\x12P\n\x10UpdateNut04Quote\x12\x1e.management.UpdateQuoteRequest\x1a\x1a.management.UpdateResponse\"\x00\x12P\n\x10UpdateNut05Quote\x12\x1e.management.UpdateQuoteRequest\x1a\x1a.management.UpdateResponse\"\x00\x12_\n\x10RotateNextKeyset\x12#.management.RotateNextKeysetRequest\x1a$.management.RotateNextKeysetResponse\"\x00\x12Y\n\x12UpdateLightningFee\x12%.management.UpdateLightningFeeRequest\x1a\x1a.management.UpdateResponse\"\x00\x12U\n\x10UpdateAuthLimits\x12#.management.UpdateAuthLimitsRequest\x1a\x1a.management.UpdateResponse\"\x00\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'management_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_GETINFOREQUEST']._serialized_start=32
  _globals['_GETINFOREQUEST']._serialized_end=48
  _globals['_MINTINFOCONTACT']._serialized_start=50
  _globals['_MINTINFOCONTACT']._serialized_end=97
  _globals['_GETINFORESPONSE']._serialized_start=100
  _globals['_GETINFORESPONSE']._serialized_end=491
  _globals['_UPDATERESPONSE']._serialized_start=493
  _globals['_UPDATERESPONSE']._serialized_end=509
  _globals['_UPDATEMOTDREQUEST']._serialized_start=511
  _globals['_UPDATEMOTDREQUEST']._serialized_end=544
  _globals['_UPDATEDESCRIPTIONREQUEST']._serialized_start=546
  _globals['_UPDATEDESCRIPTIONREQUEST']._serialized_end=593
  _globals['_UPDATEICONURLREQUEST']._serialized_start=595
  _globals['_UPDATEICONURLREQUEST']._serialized_end=635
  _globals['_UPDATENAMEREQUEST']._serialized_start=637
  _globals['_UPDATENAMEREQUEST']._serialized_end=670
  _globals['_UPDATEURLREQUEST']._serialized_start=672
  _globals['_UPDATEURLREQUEST']._serialized_end=703
  _globals['_UPDATECONTACTREQUEST']._serialized_start=705
  _globals['_UPDATECONTACTREQUEST']._serialized_end=757
  _globals['_UPDATENUT04REQUEST']._serialized_start=760
  _globals['_UPDATENUT04REQUEST']._serialized_end=940
  _globals['_UPDATENUT05REQUEST']._serialized_start=943
  _globals['_UPDATENUT05REQUEST']._serialized_end=1081
  _globals['_UPDATEQUOTETTLREQUEST']._serialized_start=1083
  _globals['_UPDATEQUOTETTLREQUEST']._serialized_end=1132
  _globals['_NUT04QUOTE']._serialized_start=1135
  _globals['_NUT04QUOTE']._serialized_end=1422
  _globals['_BLINDEDMESSAGE']._serialized_start=1424
  _globals['_BLINDEDMESSAGE']._serialized_end=1514
  _globals['_DLEQ']._serialized_start=1516
  _globals['_DLEQ']._serialized_end=1544
  _globals['_BLINDEDSIGNATURE']._serialized_start=1546
  _globals['_BLINDEDSIGNATURE']._serialized_end=1650
  _globals['_NUT05QUOTE']._serialized_start=1653
  _globals['_NUT05QUOTE']._serialized_end=2075
  _globals['_GETNUT04QUOTEREQUEST']._serialized_start=2077
  _globals['_GETNUT04QUOTEREQUEST']._serialized_end=2117
  _globals['_GETNUT04QUOTERESPONSE']._serialized_start=2119
  _globals['_GETNUT04QUOTERESPONSE']._serialized_end=2181
  _globals['_GETNUT05QUOTEREQUEST']._serialized_start=2183
  _globals['_GETNUT05QUOTEREQUEST']._serialized_end=2223
  _globals['_GETNUT05QUOTERESPONSE']._serialized_start=2225
  _globals['_GETNUT05QUOTERESPONSE']._serialized_end=2287
  _globals['_UPDATEQUOTEREQUEST']._serialized_start=2289
  _globals['_UPDATEQUOTEREQUEST']._serialized_end=2342
  _globals['_ROTATENEXTKEYSETREQUEST']._serialized_start=2344
  _globals['_ROTATENEXTKEYSETREQUEST']._serialized_end=2467
  _globals['_ROTATENEXTKEYSETRESPONSE']._serialized_start=2469
  _globals['_ROTATENEXTKEYSETRESPONSE']._serialized_end=2563
  _globals['_UPDATELIGHTNINGFEEREQUEST']._serialized_start=2565
  _globals['_UPDATELIGHTNINGFEEREQUEST']._serialized_end=2684
  _globals['_UPDATEAUTHLIMITSREQUEST']._serialized_start=2687
  _globals['_UPDATEAUTHLIMITSREQUEST']._serialized_end=2846
  _globals['_MINT']._serialized_start=2849
  _globals['_MINT']._serialized_end=4497
# @@protoc_insertion_point(module_scope)
