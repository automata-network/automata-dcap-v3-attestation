pub struct Asn1<'a> {
    der: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct NodePtr {
    pub ixs: usize,
    pub ixf: usize,
    pub ixl: usize,
}

impl NodePtr {
    pub fn forward(&self, n: usize) -> Self {
        Self {
            ixs: self.ixs + n,
            ixf: self.ixf + n,
            ixl: self.ixl,
        }
    }
}

impl<'a> Asn1<'a> {
    pub fn new(der: &'a [u8]) -> Self {
        Self { der }
    }

    pub fn root(&self) -> NodePtr {
        self.read_node(0)
    }

    pub fn first_child_of(&self, ptr: &NodePtr) -> NodePtr {
        assert!(self.der[ptr.ixs] & 0x20 == 0x20, "Not a constructed type");
        self.read_node(ptr.ixf)
    }

    pub fn byte_at(&self, ptr: &NodePtr) -> u8 {
        self.der[ptr.ixs]
    }

    pub fn all_bytes_at(&self, ptr: &NodePtr) -> &'a [u8] {
        &self.der[ptr.ixs..=ptr.ixl]
    }

    pub fn bytes_at(&self, ptr: &NodePtr) -> &'a [u8] {
        &self.der[ptr.ixf..=ptr.ixl]
    }

    pub fn root_of_octet_string_at(&self, ptr: &NodePtr) -> NodePtr {
        assert!(self.der[ptr.ixs] == 0x04, "Not type OCTET STRING");
        self.read_node(ptr.ixf)
    }

    pub fn bytes_at_limit(&self, ptr: &NodePtr, n: usize) -> &'a [u8] {
        let data = self.bytes_at(ptr);
        if data.len() > n {
            return &data[data.len()-n..];
        }
        data
    }

    pub fn next_sibling_of(&self, ptr: &NodePtr) -> NodePtr {
        self.read_node(ptr.ixl + 1)
    }

    fn read_node(&self, ix: usize) -> NodePtr {
        let length;
        let ix_first_content_byte;
        let ix_last_content_byte;
        if (self.der[ix + 1] & 0x80) == 0 {
            length = self.der[ix + 1] as usize;
            ix_first_content_byte = ix + 2;
            ix_last_content_byte = ix_first_content_byte + length - 1;
        } else {
            let length_bytes_length = self.der[ix + 1] & 0x7F;
            if length_bytes_length == 1 {
                length = self.read_u8(ix + 2) as usize;
            } else if length_bytes_length == 2 {
                length = self.read_u16(ix + 2) as usize;
            } else {
                // length = uint256(
                //     der.readBytesN(ix + 2, lengthbytesLength) >> (32 - lengthbytesLength) * 8,
                // );
                unreachable!("{}", length_bytes_length)
            }
            ix_first_content_byte = ix + 2 + length_bytes_length as usize;
            ix_last_content_byte = ix_first_content_byte + length - 1;
        }
        return NodePtr {
            ixs: ix,
            ixf: ix_first_content_byte,
            ixl: ix_last_content_byte,
        };
    }

    fn read_u8(&self, idx: usize) -> u8 {
        self.der[idx]
    }

    fn read_u16(&self, idx: usize) -> u16 {
        let mut tmp2b = [0_u8; 2];
        tmp2b.copy_from_slice(&self.der[idx..idx + 2]);
        u16::from_be_bytes(tmp2b)
    }
}
