import javax.swing.*;
import java.awt.*;

public class ComponentDemo {
    public static void main(String[] args) {
        //Creat a new window
        JFrame jf = new JFrame();
        jf.setTitle("Test");
        jf.setSize(500, 700);
        jf.setLocationRelativeTo(null);
        jf.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        //Creat multiple panels
        JTabbedPane jt = new JTabbedPane(JTabbedPane.TOP);
        JPanel panel1 = new JPanel();
        JPanel panel2 = new JPanel();
        jt.addTab("1", panel1);
        jt.addTab("2", panel2);
        jf.add(jt); //Add the panels in the window

        //Creat a button
        JButton button1 = new JButton("button 1");
        JButton button2 = new JButton("button 2");
        panel1.add(button1); //Add the button in to the panel
        panel1.add(button2);

        //Creat a menu
        JMenu jm = new JMenu("File");
        JMenuBar jmb = new JMenuBar();

        JMenuItem jmi1 = new JMenuItem("Open");
        JMenuItem jmi2 = new JMenuItem("Save");
        JMenuItem jmi3 = new JMenuItem("Close");

        JMenu jm1 = new JMenu("new");
        JMenuItem jmi4 = new JMenuItem("File");
        JMenuItem jmi5 = new JMenuItem("Directory");
        jm1.add(jmi4);
        jm1.add(jmi5);

        jm.add(jm1);
        jm.add(jmi1);
        jm.add(jmi2);
        jm.add(jmi3);

        jmb.add(jm);
        jf.setJMenuBar(jmb);

        jf.setVisible(true);
    }
}
