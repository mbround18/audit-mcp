// Deliberately flawed: exists so Java scanners have something to report.
// Contains an empty catch block, an unused local, a hardcoded credential,
// and non-conventional formatting.
package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class Insecure {
    private static final String PASSWORD = "hunter2";

    public ResultSet lookup(String userId) {
        int unusedLocal = 42;
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", PASSWORD);
            Statement stmt = conn.createStatement();
            // SQL built by string concatenation from caller-supplied input.
            return stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
        } catch (Exception e) {
        }
        return null;
    }
}
