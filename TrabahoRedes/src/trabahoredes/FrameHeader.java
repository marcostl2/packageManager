package trabahoredes;
import java.io.RandomAccessFile;

 public class FrameHeader {

    int seconds;
    int mic_secs;
    int capt_data;
    int actual_length;

    public boolean readHeader(RandomAccessFile in) {
        boolean success = true;
        try {
            seconds = in.readInt();
            mic_secs = in.readInt();
            capt_data = in.readInt();
            actual_length = in.readInt();
        } catch (Exception e) {
            success = false;
        }
        return success;
    }

    public void toBigEndian() {
        seconds = Integer.reverseBytes(seconds);
        mic_secs = Integer.reverseBytes(mic_secs);
        capt_data = Integer.reverseBytes(capt_data);
        actual_length = Integer.reverseBytes(actual_length);
    }
}
