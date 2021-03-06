/* Decoder for ASN.1 BER/DER/CER encoded bytestream
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */


/*
 *  Copyright (c) 2012-2019 Finnbarr P. Murphy.   All rights reserved.
 *
 *  Modified to work in EDKII environment.
 *
 */

#include "UefiBaseType.h"
#include <stdlib.h>
#include <stdio.h>
#include "asn1_ber_decoder.h"
#include "asn1_ber_bytecode.h"
#include <cerrno>

#define BUFF_SIZE 1000
wchar_t tmpbuf[BUFF_SIZE];

/* asn1_op_lenghts defined in asn1_ber_bytecode.h*/
static const unsigned char asn1_op_lengths[ASN1_OP__NR] = {
/*           OPC                         TAG JMP ACT */
	[ASN1_OP_MATCH]                     = 1 + 1,
	[ASN1_OP_MATCH_OR_SKIP]             = 1 + 1,
	[ASN1_OP_MATCH_ACT]                 = 1 + 1 + 1,
	[ASN1_OP_MATCH_ACT_OR_SKIP]         = 1 + 1 + 1,
	[ASN1_OP_MATCH_JUMP]                = 1 + 1 + 1,
	[ASN1_OP_MATCH_JUMP_OR_SKIP]        = 1 + 1 + 1,
	[ASN1_OP_MATCH_ANY]                 = 1,
	[ASN1_OP_MATCH_ANY_ACT]             = 1 + 1,
	[ASN1_OP_COND_MATCH_OR_SKIP]        = 1 + 1,
	[ASN1_OP_COND_MATCH_ACT_OR_SKIP]    = 1 + 1 + 1,
	[ASN1_OP_COND_MATCH_JUMP_OR_SKIP]   = 1 + 1 + 1,
	[ASN1_OP_COND_MATCH_ANY]            = 1,
	[ASN1_OP_COND_MATCH_ANY_ACT]        = 1 + 1,
	[ASN1_OP_COND_FAIL]                 = 1,
	[ASN1_OP_COMPLETE]                  = 1,
	[ASN1_OP_ACT]                       = 1 + 1,
	[ASN1_OP_RETURN]                    = 1,
	[ASN1_OP_END_SEQ]                   = 1,
	[ASN1_OP_END_SEQ_OF]                = 1 + 1,
	[ASN1_OP_END_SET]                   = 1,
	[ASN1_OP_END_SET_OF]                = 1 + 1,
	[ASN1_OP_END_SEQ_ACT]               = 1 + 1,
	[ASN1_OP_END_SEQ_OF_ACT]            = 1 + 1 + 1,
	[ASN1_OP_END_SET_ACT]               = 1 + 1,
	[ASN1_OP_END_SET_OF_ACT]            = 1 + 1 + 1
};


/*
 * Find the length of an indefinite length object
 * @data: The data buffer
 * @datalen: The end of the innermost containing element in the buffer
 * @_dp: The data parse cursor (updated before returning)
 * @_len: Where to return the size of the element.
 * @_errmsg: Where to return a pointer to an error message on error
 */
static int asn1_find_indefinite_length(const unsigned char *data, size_t datalen,
					   size_t *_dp, size_t *_len,
					   const char **_errmsg)
{
	unsigned char tag, tmp;
	size_t dp = *_dp, len, n;
	int indef_level = 1;

	next_tag:
	//if (unlikely(datalen - dp < 2)) 
	if ((datalen - dp) < 2)
	{
		if (datalen == dp)
			goto ERR_missing_eoc;
		goto ERR_data_overrun_error;
	}

	/* Extract a tag from the data */
	tag = data[dp++];
	if (tag == 0) 
	{
		/* It appears to be an EOC. */
		if (data[dp++] != 0)
		{
			goto ERR_invalid_eoc;
		}
		if (--indef_level <= 0) 
		{
			*_len = dp - *_dp;
			*_dp = dp;
			return 0;
		}
		goto next_tag;
	}

	//if (unlikely((tag & 0x1f) == 0x1f)) 
	if ((tag & 0x1f) == 0x1f)
	{
		do {
			//if (unlikely(datalen - dp < 2))
			if ((datalen - dp) < 2)
			{
				goto ERR_data_overrun_error;
			}
			tmp = data[dp++];
		} while (tmp & 0x80);
	}

	/* Extract the length */
	len = data[dp++];
	if (len < 0x7f) {
		dp += len;
		goto next_tag;
	}

	//if (unlikely(len == 0x80)) 
	if (len == 0x80)
	{
		/* Indefinite length */
		//if (unlikely((tag & ASN1_CONS_BIT) == ASN1_PRIM << 5))
		if ((tag & ASN1_CONS_BIT) == (ASN1_PRIM << 5))
		{
			goto ERR_indefinite_len_primitive;
		}
		indef_level++;
		goto next_tag;
	}

	n = len - 0x80;
	//if (unlikely(n > sizeof(size_t) - 1))
	if (n > (sizeof(size_t) - 1) )
	{
		goto ERR_length_too_long;
	}
	//if (unlikely(n > datalen - dp))
	if (n > (datalen - dp))
	{
		goto ERR_data_overrun_error;
	}
	for (len = 0; n > 0; n--) {
		len <<= 8;
		len |= data[dp++];
	}
	dp += len;
	goto next_tag;

	/* 
	 *  FPM - have not touched these messages. need to study code path.
	 *		if you get garbled output, these may be the culprits
	 * 
	 */
	ERR_length_too_long:
		*_errmsg = "Unsupported length";
		goto error;
	ERR_indefinite_len_primitive:
		*_errmsg = "Indefinite len primitive not permitted";
		goto error;
	ERR_invalid_eoc:
		*_errmsg = "Invalid length EOC";
		goto error;
	ERR_data_overrun_error:
		*_errmsg = "Data overrun error";
		goto error;
	ERR_missing_eoc:
		*_errmsg = "Missing EOC in indefinite len cons";
	error:
		*_dp = dp;
		return -1;
}

/**
 * asn1_ber_decoder - Decoder BER/DER/CER ASN.1 according to pattern
 * @decoder: The decoder definition (produced by asn1_compiler)
 * @context: The caller's context (to be passed to the action functions)
 * @data: The encoded data
 * @datasize: The size of the encoded data
 *
 * Decode BER/DER/CER encoded ASN.1 data according to a bytecode pattern
 * produced by asn1_compiler.  Action functions are called on marked tags to
 * allow the caller to retrieve significant data.
 *
 * LIMITATIONS:
 *
 * To keep down the amount of stack used by this function, the following limits
 * have been imposed:
 *
 *  (1) This won't handle datalen > 65535 without increasing the size of the
 *	cons stack elements and length_too_long checking.
 *
 *  (2) The stack of constructed types is 10 deep.  If the depth of non-leaf
 *	constructed types exceeds this, the decode will fail.
 *
 *  (3) The SET type (not the SET OF type) isn't really supported as tracking
 *	what members of the set have been seen is a pain.
 */
int asn1_ber_decoder(const struct asn1_decoder *decoder,
			 void *context,
			 const unsigned char *data,
			 size_t datalen)
{
	const unsigned char *machine = decoder->machine;
	const asn1_action_t *actions = decoder->actions;
	size_t machlen = decoder->machlen;
	enum asn1_opcode op;
	unsigned char tag = 0, csp = 0, jsp = 0, optag = 0, hdr = 0;
	const char *errmsg;
	const wchar_t *Errmsg = NULL;
	size_t pc = 0, dp = 0, tdp = 0, len = 0;
	int ret;

	unsigned char flags = 0;
	#define FLAG_INDEFINITE_LENGTH	0x01
	#define FLAG_MATCHED			0x02
	#define FLAG_CONS				0x20 /* Corresponds to CONS bit in the opcode tag
										  * - ie. whether or not we are going to parse
										  *   a compound type.
										  */

	#define NR_CONS_STACK 10
	unsigned short cons_dp_stack[NR_CONS_STACK];
	unsigned short cons_datalen_stack[NR_CONS_STACK];
	unsigned char cons_hdrlen_stack[NR_CONS_STACK];
	#define NR_JUMP_STACK 10
	unsigned char jump_stack[NR_JUMP_STACK];

	if (datalen > 65535)
	{
		return -EMSGSIZE;
	}

	next_op:
	//if (unlikely(pc >= machlen))
	if (pc >= machlen)
	{
		goto ERR_machine_overrun_error;
	}
	op = machine[pc];	//Cross-reference against x509.c static const unsigned char x509_machine[]

	//if (unlikely(pc + asn1_op_lengths[op] > machlen))
	if ((pc + asn1_op_lengths[op]) > machlen)
	{
		goto ERR_machine_overrun_error;
	}

	/* If this command is meant to match a tag, then do that before
	 * evaluating the command.
	 */
	if (op <= ASN1_OP__MATCHES_TAG) 
	{
		unsigned char tmp;

		/* Skip conditional matches if possible */
		if ( ((op & ASN1_OP_MATCH__COND) && (flags & FLAG_MATCHED)
			) || (dp == datalen) ) 
		{
			pc += asn1_op_lengths[op];
			goto next_op;
		}

		flags = 0;
		hdr = 2;

		/* Extract a tag from the data */
		//if (unlikely(dp >= datalen - 1))
		if (dp >= (datalen - 1))
		{
			goto ERR_data_overrun_error;
		}
		tag = data[dp++];
		//if (unlikely((tag & 0x1f) == 0x1f))
		if ((tag & 0x1f) == 0x1f)
		{
			goto ERR_long_tag_not_supported;
		}

		
		if (op & ASN1_OP_MATCH__ANY) 
		{
			;	//I dislike hanging semicolons, should examine this block's purpose
		} 
		else
		{
			/* Extract the tag from the machine
			 * - Either CONS or PRIM are permitted in the data if
			 *   CONS is not set in the op stream, otherwise CONS
			 *   is mandatory.
			 */
			optag = machine[pc + 1];
			flags |= optag & FLAG_CONS;

			/* Determine whether the tag matched */
			tmp = optag ^ tag;
			tmp &= ~(optag & ASN1_CONS_BIT);
			if (tmp != 0) 
			{
				/* All odd-numbered tags are MATCH_OR_SKIP. */
				if (op & ASN1_OP_MATCH__SKIP) 
				{
					pc += asn1_op_lengths[op];
					dp--;
					goto next_op;
				}
				goto ERR_tag_mismatch;
			}
		}
		flags |= FLAG_MATCHED;

		len = data[dp++];
		if (len > 0x7f) 
		{
			//if (unlikely(len == 0x80)) 
			if (len == 0x80)
			{
				/* Indefinite length */
				//if (unlikely(!(tag & ASN1_CONS_BIT)))
				if (!(tag & ASN1_CONS_BIT))
				{
					goto ERR_indefinite_len_primitive;
				}
				flags |= FLAG_INDEFINITE_LENGTH;
				//if (unlikely(2 > datalen - dp))
				if (2 > (datalen - dp))
				{
					goto ERR_data_overrun_error;
				}
			} 
			else {
				size_t n = len - 0x80;
				//if (unlikely(n > 2))
				if (n > 2)
				{
					goto ERR_length_too_long;
				}
				//if (unlikely(dp >= datalen - n))
				if (dp >= (datalen - n))
				{
					goto ERR_data_overrun_error;
				}
				hdr += n; //TODO: WARNING C4267 : '+=' : conversion from 'size_t' to 'unsigned char', possible loss of data
				for (len = 0; n > 0; n--) {
					len <<= 8;
					len |= data[dp++];
				}
				//if (unlikely(len > datalen - dp))
				if (len > (datalen - dp))
				{
					goto ERR_data_overrun_error;
				}
			}
		}

		if (flags & FLAG_CONS) 
		{
			/* For expected compound forms, we stack the positions
			 * of the start and end of the data.
			 */
			//if (unlikely(csp >= NR_CONS_STACK))
			if (csp >= NR_CONS_STACK)
			{
				goto ERR_cons_stack_overflow;
			}
			cons_dp_stack[csp] = dp; //TODO: WARNING C4267 : '+=' : conversion from 'size_t' to 'unsigned short', possible loss of data
			cons_hdrlen_stack[csp] = hdr;
			if (!(flags & FLAG_INDEFINITE_LENGTH)) 
			{
				cons_datalen_stack[csp] = datalen; //TODO: WARNING C4267 : '+=' : conversion from 'size_t' to 'unsigned short', possible loss of data
				datalen = dp + len;
			} 
			else 
			{
				cons_datalen_stack[csp] = 0;
			}
			csp++;
		}

		tdp = dp;
	}

	/* Decide how to handle the operation */
	switch (op) 
	{
		case ASN1_OP_MATCH_ANY_ACT:
		case ASN1_OP_COND_MATCH_ANY_ACT:
			ret = actions[machine[pc + 1]](context, hdr, tag, data + dp, len);
			if (ret < 0)
			{
				return ret;
			}
			goto skip_data;

		case ASN1_OP_MATCH_ACT:
		case ASN1_OP_MATCH_ACT_OR_SKIP:
		case ASN1_OP_COND_MATCH_ACT_OR_SKIP:
			ret = actions[machine[pc + 2]](context, hdr, tag, data + dp, len);
			if (ret < 0)
			{
				return ret;
			}
			goto skip_data;

		case ASN1_OP_MATCH:
		case ASN1_OP_MATCH_OR_SKIP:
		case ASN1_OP_MATCH_ANY:
		case ASN1_OP_COND_MATCH_OR_SKIP:
		case ASN1_OP_COND_MATCH_ANY:
			skip_data:
				if (!(flags & FLAG_CONS)) 
				{
					if (flags & FLAG_INDEFINITE_LENGTH) 
					{
						ret = asn1_find_indefinite_length(data, datalen, &dp, &len, &errmsg);
						if (ret < 0)
						{
							return ret;
						}
					} 
					else 
					{
						dp += len;
					}
				}
				pc += asn1_op_lengths[op];
				goto next_op;

		case ASN1_OP_MATCH_JUMP:
		case ASN1_OP_MATCH_JUMP_OR_SKIP:
		case ASN1_OP_COND_MATCH_JUMP_OR_SKIP:
			//if (unlikely(jsp == NR_JUMP_STACK))
			if (jsp == NR_JUMP_STACK)
			{
				goto ERR_jump_stack_overflow;
			}
			jump_stack[jsp++] = pc + asn1_op_lengths[op]; //TODO: WARNING C4267 : '+=' : conversion from 'size_t' to 'unsigned char', possible loss of data
			pc = machine[pc + 2];
			goto next_op;

		case ASN1_OP_COND_FAIL:
			//if (unlikely(!(flags & FLAG_MATCHED)))
			if (!(flags & FLAG_MATCHED))
			{
				goto ERR_tag_mismatch;
			}
			pc += asn1_op_lengths[op];
			goto next_op;

		case ASN1_OP_COMPLETE:
			//if (unlikely(jsp != 0 || csp != 0)) 
			if (jsp != 0 || csp != 0)
			{
				goto ERR_unspecified;
				//return -EBADMSG;
			}
			return 0;

		case ASN1_OP_END_SET:
		case ASN1_OP_END_SET_ACT:
			//if (unlikely(!(flags & FLAG_MATCHED)))
			if (!(flags & FLAG_MATCHED))
			{
				goto ERR_tag_mismatch;
			}
		case ASN1_OP_END_SEQ:
		case ASN1_OP_END_SET_OF:
		case ASN1_OP_END_SEQ_OF:
		case ASN1_OP_END_SEQ_ACT:
		case ASN1_OP_END_SET_OF_ACT:
		case ASN1_OP_END_SEQ_OF_ACT:
			//if (unlikely(csp <= 0))
			if (csp <= 0)
			{
				goto ERR_cons_stack_underflow;
			}
			csp--;
			tdp = cons_dp_stack[csp];
			hdr = cons_hdrlen_stack[csp];
			len = datalen;
			datalen = cons_datalen_stack[csp];
			if (datalen == 0) 
			{
				/* Indefinite length - check for the EOC. */
				datalen = len;
				//if (unlikely(datalen - dp < 2))
				if ((datalen - dp) < 2)
				{
					goto ERR_data_overrun_error;
				}
				if (data[dp++] != 0) 
				{
					if (op & ASN1_OP_END__OF) 
					{
						dp--;
						csp++;
						pc = machine[pc + 1];
						goto next_op;
					}
					goto ERR_missing_eoc;
				}
				if (data[dp++] != 0)
				{
					goto ERR_invalid_eoc;
				}
				len = dp - tdp - 2;
			} 
			else 
			{
				if ((dp < len) && (op & ASN1_OP_END__OF)) 
				{
					datalen = len;
					csp++;
					pc = machine[pc + 1];
					goto next_op;
				}
				if (dp != len)
				{
					goto ERR_cons_length_error;
				}
				len -= tdp;
			}

			if (op & ASN1_OP_END__ACT) 
			{
				unsigned char act;
				if (op & ASN1_OP_END__OF)
				{
					act = machine[pc + 2];
				}
				else
				{
					act = machine[pc + 1];
				}
				ret = actions[act](context, hdr, 0, data + tdp, len);
			}
			pc += asn1_op_lengths[op];
			goto next_op;

		case ASN1_OP_ACT:
			ret = actions[machine[pc + 1]](context, hdr, tag, data + tdp, len);
			pc += asn1_op_lengths[op];
			goto next_op;

		case ASN1_OP_RETURN:
			//if (unlikely(jsp <= 0))
			if (jsp <= 0)
			{
				goto ERR_jump_stack_underflow;
			}
			pc = jump_stack[--jsp];
			goto next_op;
		default:
			break;
	}

	/* Shouldn't reach here */
	return -EBADMSG;
	ERR_unspecified:
		Errmsg = L"Unspecified asn1_ber_decoder error";
		goto error;
	ERR_data_overrun_error:
		Errmsg = L"Data overrun error";
		goto error;
	ERR_machine_overrun_error:
		Errmsg = L"Machine overrun error";
		goto error;
	ERR_jump_stack_underflow:
		Errmsg = L"Jump stack underflow";
		goto error;
	ERR_jump_stack_overflow:
		Errmsg = L"Jump stack overflow";
		goto error;
	ERR_cons_stack_underflow:
		Errmsg = L"Cons stack underflow";
		goto error;
	ERR_cons_stack_overflow:
		Errmsg = L"Cons stack overflow";
		goto error;
	ERR_cons_length_error:
		Errmsg = L"Cons length error";
		goto error;
	ERR_missing_eoc:
		Errmsg = L"Missing EOC in indefinite len cons";
		goto error;
	ERR_invalid_eoc:
		Errmsg = L"Invalid length EOC";
		goto error;
	ERR_length_too_long:
		Errmsg = L"Unsupported length";
		goto error;
	ERR_indefinite_len_primitive:
		Errmsg = L"Indefinite len primitive not permitted";
		goto error;
	ERR_tag_mismatch:
		Errmsg = L"Unexpected tag";
		goto error;
	ERR_long_tag_not_supported:
		Errmsg = L"Long tag not supported";
	error:
		//memset(tmpbuf, 0, BUFF_SIZE); //TODO : this wasn't in the original fpmurphy code, so not sure why I added data sanitation here
		swprintf_s(tmpbuf,BUFF_SIZE,L"ERROR: %ls\n", Errmsg);
		printf_s("%ls", tmpbuf);
	return -EBADMSG;
}

