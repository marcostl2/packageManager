package trabahoredes;

import java.io.RandomAccessFile;

public class TcpDumpHeader {

    int magic_number;
    short major_version;
    short minor_version;
    int time_zone_off;
    int time_stamp;
    int snap_length;
    int link_layer_type;

    public boolean readHeader(RandomAccessFile in) {
        boolean success = true;
        try {
            magic_number = in.readInt();
            major_version = in.readShort();
            minor_version = in.readShort();
            time_zone_off = in.readInt();
            time_stamp = in.readInt();
            snap_length = in.readInt();
            link_layer_type = in.readInt();
        } catch (Exception e) {
            success = false;
        }
        return success;
    }

    public boolean isLittleEndian() {
        if (!Integer.toHexString(magic_number).equals("a1b2c3d4")) {
            return true;
        } else {
            return false;
        }
    }

    public void toBigEndian() {
        magic_number = Integer.reverseBytes(magic_number);
        major_version = Short.reverseBytes(major_version);
        minor_version = Short.reverseBytes(minor_version);
        time_zone_off = Integer.reverseBytes(time_zone_off);
        time_stamp = Integer.reverseBytes(time_stamp);
        snap_length = Integer.reverseBytes(snap_length);
        link_layer_type = Integer.reverseBytes(link_layer_type);
    }
}
