import javax.swing.*;

public class JDialogDemo {
    public static void main(String[] args) {
        //Set a outside window
        JFrameDemo frame = new JFrameDemo();

        //Set a inner window
        JDialog jd = new JDialog();
        jd.setSize(200, 300);
        jd.setTitle("inner");
        jd.setVisible(true);
        jd.setLocationRelativeTo(null);
    }
}
