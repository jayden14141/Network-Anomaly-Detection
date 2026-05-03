import javax.swing.*;

public class JFrameDemo extends JFrame {
    public JFrameDemo() {
        setTitle("Test"); //Set the title of the window
        setSize(300, 400); //Set the size of the window
        setLocationRelativeTo(null); //Set the location of the window display
        setVisible(true); //Set the window display on the screen
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE); //Set the close way
    }

    public static void main(String[] args) {
        JFrameDemo test = new JFrameDemo();
    }
}
