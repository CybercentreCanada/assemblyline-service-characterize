import struct

from assemblyline.common.str_utils import safe_str

LinkFlags_def = ['HasLinkTargetIDList',
                 'HasLinkInfo',
                 'HasName',
                 'HasRelativePath',
                 'HasWorkingDir',
                 'HasArguments',
                 'HasIconLocation',
                 'IsUnicode',
                 'ForceNoLinkInfo',
                 'HasExpString',
                 'RunInSeparateProcess',
                 'Unused1',
                 'HasDarwinID',
                 'RunAsUser',
                 'HasExpIcon',
                 'NoPidlAlias',
                 'Unused2',
                 'RunWithShimLayer',
                 'ForceNoLinkTrack',
                 'EnableTargetMetadata',
                 'DisableLinkPathTracking',
                 'DisableKnownFolderTracking',
                 'DisableKnownFolderAlias',
                 'AllowLinkToLink',
                 'UnaliasOnSave',
                 'PreferEnvironmentPath',
                 'KeepLocalIDListForUNCTarget']

FileAttributes_def = ['FILE_ATTRIBUTE_READONLY',
                      'FILE_ATTRIBUTE_HIDDEN',
                      'FILE_ATTRIBUTE_SYSTEM',
                      'Reserved1',
                      'FILE_ATTRIBUTE_DIRECTORY',
                      'FILE_ATTRIBUTE_ARCHIVE',
                      'Reserved2',
                      'FILE_ATTRIBUTE_NORMAL',
                      'FILE_ATTRIBUTE_TEMPORARY',
                      'FILE_ATTRIBUTE_SPARSE_FILE',
                      'FILE_ATTRIBUTE_REPARSE_POINT',
                      'FILE_ATTRIBUTE_COMPRESSED',
                      'FILE_ATTRIBUTE_OFFLINE',
                      'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',
                      'FILE_ATTRIBUTE_ENCRYPTED']

LinkInfoFlags_def = ['VolumeIDAndLocalBasePath',
                     'CNRLAndPathSuffix']

CNRLFlags_def = ['ValidDevice',
                 'ValidNetType']


NetworkProviderType_enum = {
    0x001A0000: 'WNNC_NET_AVID',
    0x001B0000: 'WNNC_NET_DOCUSPACE',
    0x001C0000: 'WNNC_NET_MANGOSOFT',
    0x001D0000: 'WNNC_NET_SERNET',
    0X001E0000: 'WNNC_NET_RIVERFRONT1',
    0x001F0000: 'WNNC_NET_RIVERFRONT2',
    0x00200000: 'WNNC_NET_DECORB',
    0x00210000: 'WNNC_NET_PROTSTOR',
    0x00220000: 'WNNC_NET_FJ_REDIR',
    0x00230000: 'WNNC_NET_DISTINCT',
    0x00240000: 'WNNC_NET_TWINS',
    0x00250000: 'WNNC_NET_RDR2SAMPLE',
    0x00260000: 'WNNC_NET_CSC',
    0x00270000: 'WNNC_NET_3IN1',
    0x00290000: 'WNNC_NET_EXTENDNET',
    0x002A0000: 'WNNC_NET_STAC',
    0x002B0000: 'WNNC_NET_FOXBAT',
    0x002C0000: 'WNNC_NET_YAHOO',
    0x002D0000: 'WNNC_NET_EXIFS',
    0x002E0000: 'WNNC_NET_DAV',
    0x002F0000: 'WNNC_NET_KNOWARE',
    0x00300000: 'WNNC_NET_OBJECT_DIRE',
    0x00310000: 'WNNC_NET_MASFAX',
    0x00320000: 'WNNC_NET_HOB_NFS',
    0x00330000: 'WNNC_NET_SHIVA',
    0x00340000: 'WNNC_NET_IBMAL',
    0x00350000: 'WNNC_NET_LOCK',
    0x00360000: 'WNNC_NET_TERMSRV',
    0x00370000: 'WNNC_NET_SRT',
    0x00380000: 'WNNC_NET_QUINCY',
    0x00390000: 'WNNC_NET_OPENAFS',
    0X003A0000: 'WNNC_NET_AVID1',
    0x003B0000: 'WNNC_NET_DFS',
    0x003C0000: 'WNNC_NET_KWNP',
    0x003D0000: 'WNNC_NET_ZENWORKS',
    0x003E0000: 'WNNC_NET_DRIVEONWEB',
    0x003F0000: 'WNNC_NET_VMWARE',
    0x00400000: 'WNNC_NET_RSFX',
    0x00410000: 'WNNC_NET_MFILES',
    0x00420000: 'WNNC_NET_MS_NFS',
    0x00430000: 'WNNC_NET_GOOGLE',
    None:       'INVALID'
}

showCommand_enum = {
        0x1: 'SW_SHOWNORMAL',
        0x3: 'SW_SHOWMAXIMIZED',
        0x7: 'SW_SHOWMINNOACTIVE',
        None: 'SW_SHOWNORMAL'
    }


def parse_bitmask(mask_def, mask):
    i = 0
    out = []
    while mask != 0:
        if mask & 1:
            try:
                out.append(mask_def[i])
            except IndexError:
                pass
        mask >>= 1
        i += 1
    return out


def parse_enumeration(enum_def, val):
    if val not in enum_def:
        return enum_def[None]
    else:
        return enum_def[val]


def parse_pstr(data, is_utf16):
    n_len, = struct.unpack('<H', data[:2])
    if is_utf16:
        n_len *= 2
    out_str = data[2: 2 + n_len]
    if is_utf16:
        out_str = out_str.decode('utf-16')
    data = data[2 + n_len:]
    return data, out_str


def extract_value(data, offset, end=b'\x00', is_utf16=True):
    value = data[offset:].split(end, 1)[0]
    if is_utf16:
        return value.decode("utf-16", errors='ignore')
    else:
        return safe_str(value)


def decode_lnk(lnk, parse_tidlist=False):
    """ See MS-SHLLINK """
    try:
        metadata = {}
        headersize, linkclsid, link_flags, file_atributes, ctime, atime, mtime, \
            fsize, icon_index, show_command, hot_key, \
            r1, r2, r3 = struct.unpack('<I16sIIQQQIIIHHII', lnk[:76])

        if headersize != 76 or linkclsid != b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F':
            return None

        show_command = parse_enumeration(showCommand_enum, show_command)

        link_flags = parse_bitmask(LinkFlags_def, link_flags)
        file_atributes = parse_bitmask(FileAttributes_def, file_atributes)

        metadata['showCommand'] = show_command
        metadata['linkFlags'] = link_flags
        metadata['fileAtributes'] = file_atributes

        lnk = lnk[76:]

        is_utf16 = 'IsUnicode' in link_flags

        if 'HasLinkTargetIDList' in link_flags:
            ltid_len, = struct.unpack('<H', lnk[:2])
            link_target_id_list = lnk[2:ltid_len+2]
            lnk = lnk[ltid_len+2:]

            if parse_tidlist:
                # The spec doesn't give a clear indication of why this is needed.
                # So I've made it optional and disabled by default.
                id_list = [[]]
                while link_target_id_list:
                    if link_target_id_list[0:2] == b'\x00\x00':
                        id_list.append([])
                        link_target_id_list = link_target_id_list[2:]
                    else:
                        itm_size, = struct.unpack('<H', link_target_id_list[0:2])
                        id_list[-1].append(link_target_id_list[2:itm_size])
                        link_target_id_list = link_target_id_list[itm_size:]
                id_list.pop(-1)
                metadata['IDList'] = id_list

        if 'HasLinkInfo' in link_flags:
            link_info_size, link_info_header_size, link_info_flags, volume_id_offset, local_base_path_offset, \
                cnrl_offset, common_path_suffix_offset = struct.unpack('<IIIIIII', lnk[:28])

            link_info = lnk[:link_info_size]
            lnk = lnk[link_info_size:]

            link_info_flags = parse_bitmask(LinkInfoFlags_def, link_info_flags)

            if 'VolumeIDAndLocalBasePath' in link_info_flags:
                vid = {}
                volume_id_size, drive_type, drive_serial_number, volume_label_offset, volume_label_offset_unicode = \
                    struct.unpack('<IIIII', link_info[volume_id_offset:volume_id_offset+20])
                vid['DriveType'] = ['DRIVE_UNKNOWN', 'DRIVE_NO_ROOT_DIR', 'DRIVE_REMOVABLE', 'DRIVE_FIXED',
                                    'DRIVE_REMOTE', 'DRIVE_CDROM', 'DRIVE_RAMDISK'][drive_type]
                vid['DriveSerialNumber'] = drive_serial_number
                vid['VolumeLabel'] = extract_value(link_info, volume_id_offset + volume_label_offset, is_utf16=is_utf16)

                if volume_label_offset == 0x14:
                    vid['VolumeLabelUnicode'] = extract_value(link_info,
                                                              volume_id_offset + volume_label_offset_unicode,
                                                              end=b'\x00\x00', is_utf16=is_utf16)

                metadata['BasePath'] = extract_value(link_info, local_base_path_offset, is_utf16=False)
                metadata['VolumeID'] = vid

            if 'CNRLAndPathSuffix' in link_info_flags:
                cnrlo = {}
                cnrl_size, cnrl_flags, net_name_offset, device_name_offset, \
                    network_provider_type = struct.unpack("<IIIII", link_info[cnrl_offset:cnrl_offset+20])

                cnrl_flags = parse_bitmask(CNRLFlags_def, cnrl_flags)

                metadata['NetName'] = extract_value(link_info, cnrl_offset + net_name_offset, is_utf16=is_utf16)

                if 'ValidDevice' in cnrl_flags:
                    cnrlo['DeviceName'] = extract_value(link_info, cnrl_offset + device_name_offset, is_utf16=is_utf16)

                if 'ValidNetType' in cnrl_flags:
                    cnrlo['NetworkProviderType'] = parse_enumeration(NetworkProviderType_enum, network_provider_type)

                if cnrl_size > 0x14:
                    net_name_offset_unicode, device_name_offset_unicode = \
                        struct.unpack("<II", link_info[cnrl_offset + 20:cnrl_offset + 28])

                    cnrlo['NetNameUnicode'] = extract_value(link_info, cnrl_offset + net_name_offset_unicode,
                                                            end=b'\x00\x00', is_utf16=is_utf16)
                    cnrlo['DeviceNameUnicode'] = extract_value(link_info, cnrl_offset + device_name_offset_unicode,
                                                               end=b'\x00\x00', is_utf16=is_utf16)

                metadata['CommonNetworkRelativeLink'] = cnrlo

        # String data
        if 'HasName' in link_flags:
            lnk, metadata['NAME_STRING'] = parse_pstr(lnk, is_utf16)
        if 'HasRelativePath' in link_flags:
            lnk, metadata['RELATIVE_PATH'] = parse_pstr(lnk, is_utf16)
        if 'HasWorkingDir' in link_flags:
            lnk, metadata['WORKING_DIR'] = parse_pstr(lnk, is_utf16)
        if 'HasArguments' in link_flags:
            lnk, metadata['COMMAND_LINE_ARGUMENTS'] = parse_pstr(lnk, is_utf16)
        if 'HasIconLocation' in link_flags:
            lnk, metadata['ICON_LOCATION'] = parse_pstr(lnk, is_utf16)

        # Note: there is technically an "ExtraData" block after the strings.
        # But I couldn't find anything in them that was worth parsing out.

        return metadata

    except struct.error:
        # Not enough bytes in the file
        return None


if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fh:
        print(decode_lnk(fh.read()))
