/*
 * Copyright 2004-2013 H2 Group. Multiple-Licensed under the H2 License,
 * Version 1.0, and under the Eclipse Public License, Version 1.0
 * (http://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.test.synth;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.BatchUpdateException;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.util.*;

import org.h2.api.ErrorCode;
import org.h2.jdbc.JdbcConnection;
import org.h2.store.FileLister;
import org.h2.store.fs.FileUtils;
import org.h2.test.TestAll;
import org.h2.test.TestBase;
import org.h2.test.db.TestScript;
import org.h2.test.synth.sql.RandomGen;
import org.h2.tools.Backup;
import org.h2.tools.DeleteDbFiles;
import org.h2.tools.Restore;
import org.h2.util.MathUtils;
import org.h2.util.New;

/**
 * A test that calls random methods with random parameters from JDBC objects.
 * This is sometimes called 'Fuzz Testing'.
 */
public class TestCrashAPI extends TestBase implements Runnable {

    private static final boolean RECOVER_ALL = false;

    private static final Class<?>[] INTERFACES = { Connection.class,
            PreparedStatement.class, Statement.class, ResultSet.class,
            ResultSetMetaData.class, Savepoint.class, ParameterMetaData.class,
            Clob.class, Blob.class, Array.class, CallableStatement.class };

    private static final String DIR = "synth";

    private final List<Object> objects = New.arrayList();
    private final Map<Class <?>, List<Method>> classMethods = New.hashMap();
    private RandomGen random = new RandomGen();
    private final ArrayList<String> statements = New.arrayList();
    private int openCount;
    private long callCount;
    private volatile long maxWait = 60;
    private volatile boolean stopped;
    private volatile boolean running;
    private Thread mainThread;

    /**
     * Run just this test.
     *
     * @param a ignored
     */
    public static void main(String... a) throws Exception {
        System.setProperty("h2.delayWrongPasswordMin", "0");
        System.setProperty("h2.delayWrongPasswordMax", "0");
        TestBase.createCaller().init().test();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void run() {
        while (--maxWait > 0) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                maxWait++;
                // ignore
            }
            if (maxWait > 0 && maxWait <= 10) {
                println("stopping...");
                stopped = true;
            }
        }
        if (maxWait == 0 && running) {
            objects.clear();
            if (running) {
                println("stopping (force)...");
                for (StackTraceElement e : mainThread.getStackTrace()) {
                    System.out.println(e.toString());
                }
                mainThread.stop(new SQLException("stop"));
            }
        }
    }

    private static void recoverAll() {
        org.h2.Driver.load();
        File[] files = new File("temp/backup").listFiles();
        Arrays.sort(files, new Comparator<File>() {
            @Override
            public int compare(File o1, File o2) {
                return o1.getName().compareTo(o2.getName());
            }
        });
        for (File f : files) {
            if (!f.getName().startsWith("db-")) {
                continue;
            }
            DeleteDbFiles.execute("data", null, true);
            try {
                Restore.execute(f.getAbsolutePath(), "data", null);
            } catch (Exception e) {
                System.out.println(f.getName() + " restore error " + e);
                // ignore
            }
            ArrayList<String> dbFiles = FileLister.getDatabaseFiles("data", null, false);
            for (String name: dbFiles) {
                if (!name.endsWith(".h2.db")) {
                    continue;
                }
                name = name.substring(0, name.length() - 6);
                try {
                    DriverManager.getConnection("jdbc:h2:data/" + name, "sa", "").close();
                    System.out.println(f.getName() + " OK");
                } catch (SQLException e) {
                    System.out.println(f.getName() + " " + e);
                }
            }
        }
    }

    @Override
    public void test() throws Exception {
        if (RECOVER_ALL) {
            recoverAll();
            return;
        }
        if (config.mvcc || config.networked) {
            return;
        }
        int len = getSize(2, 6);
        Thread t = new Thread(this);
        try {
            mainThread = Thread.currentThread();
            t.start();
            running = true;
            for (int i = 0; i < len && !stopped; i++) {
                int seed = MathUtils.randomInt(Integer.MAX_VALUE);
                testCase(seed);
                deleteDb();
            }
        } finally {
            running = false;
            deleteDb();
            maxWait = -1;
            t.join();
        }
    }

    private void deleteDb() {
        try {
            deleteDb(getBaseDir() + "/" + DIR, null);
        } catch (Exception e) {
            // ignore
        }
    }

    private Connection getConnection(int seed, boolean delete) throws SQLException {
        openCount++;
        if (delete) {
            deleteDb();
        }
        // can not use FILE_LOCK=NO, otherwise something could be written into
        // the database in the finalize method

        String add = ";MAX_QUERY_TIMEOUT=10000";

//         int testing;
//        if(openCount >= 32) {
//            int test;
//            Runtime.getRuntime().halt(0);
//            System.exit(1);
//        }
        // System.out.println("now open " + openCount);
        // add += ";TRACE_LEVEL_FILE=3";
        // config.logMode = 2;
        // }

        String dbName = "crashApi" + seed;
        String url = getURL(DIR + "/" + dbName, true) + add;

//        int test;
//        url += ";DB_CLOSE_ON_EXIT=FALSE";
//      int test;
//      url += ";TRACE_LEVEL_FILE=3";

        Connection conn = null;
        String fileName = "temp/backup/db-" + uniqueId++ + ".zip";
        Backup.execute(fileName, getBaseDir() + "/" + DIR, dbName, true);
        // close databases earlier
        System.gc();
        try {
            conn = DriverManager.getConnection(url, "sa", getPassword(""));
            // delete the backup if opening was successful
            FileUtils.delete(fileName);
        } catch (SQLException e) {
            if (e.getErrorCode() == ErrorCode.WRONG_USER_OR_PASSWORD) {
                // delete if the password changed
                FileUtils.delete(fileName);
            }
            throw e;
        }
        int len = random.getInt(50);
        int first = random.getInt(statements.size() - len);
        int end = first + len;
        Statement stat = conn.createStatement();
        stat.execute("SET LOCK_TIMEOUT 10");
        stat.execute("SET WRITE_DELAY 0");
        if (random.nextBoolean()) {
            if (random.nextBoolean()) {
                double g = random.nextGaussian();
                int size = (int) Math.abs(10000 * g * g);
                stat.execute("SET CACHE_SIZE " + size);
            } else {
                stat.execute("SET CACHE_SIZE 0");
            }
        }
        stat.execute("SCRIPT NOPASSWORDS NOSETTINGS");
        for (int i = first; i < end && i < statements.size() && !stopped; i++) {
            try {
                stat.execute("SELECT * FROM TEST WHERE ID=1");
            } catch (Throwable t) {
                printIfBad(seed, -i, -1, t);
            }
            try {
                stat.execute("SELECT * FROM TEST WHERE ID=1 OR ID=1");
            } catch (Throwable t) {
                printIfBad(seed, -i, -1, t);
            }

            String sql = statements.get(i);
            try {
//                if(openCount == 32) {
//                    int test;
//                    System.out.println("stop!");
//                }
                stat.execute(sql);
            } catch (Throwable t) {
                printIfBad(seed, -i, -1, t);
            }
        }
        if (random.nextBoolean()) {
            try {
                conn.commit();
            } catch (Throwable t) {
                printIfBad(seed, 0, -1, t);
            }
        }
        return conn;
    }

    @Override
    public void testCase(int seed) throws SQLException {
        printTime("seed: " + seed);
        callCount = 0;
        openCount = 0;
        random = new RandomGen();
        random.setSeed(seed);
        Connection c1 = getConnection(seed, true);
        Connection conn = null;
        List<RuntimeException> unsupportedOps = new ArrayList<>();
        for (int i = 0; i < 2000 && !stopped; i++) {
            if (objects.isEmpty()) {
                try {
                    conn = getConnection(seed, false);
                } catch (SQLException e) {
                    if ("08004".equals(e.getSQLState())) {
                        // Wrong user/password [08004]
                        try {
                            c1.createStatement().execute("SET PASSWORD ''");
                        } catch (Throwable t) {
                            // power off or so
                            break;
                        }
                        try {
                            long start = System.currentTimeMillis();
                            conn = getConnection(seed, false);
                            long connectTime = System.currentTimeMillis() - start;
                            if (connectTime > 2000) {
                                System.out.println("??? connected2 in " + connectTime);
                            }
                        } catch (Throwable t) {
                            printIfBad(seed, -i, -1, t);
                        }
                    } else if ("90098".equals(e.getSQLState())) {
                        // The database has been closed
                        break;
                    } else {
                        printIfBad(seed, -i, -1, e);
                    }
                }
                objects.add(conn);
            }
            int objectId = random.getInt(objects.size());
            if (random.getBoolean(1)) {
                objects.remove(objectId);
                continue;
            }
            if (random.getInt(2000) == 0 && conn != null) {
                ((JdbcConnection) conn).setPowerOffCount(random.getInt(50));
            }
            Object o = objects.get(objectId);
            if (o == null) {
                objects.remove(objectId);
                continue;
            }
            Class<?> in = getJdbcInterface(o);
            List<Method> methods = classMethods.get(in);
            Method m = methods.get(random.getInt(methods.size()));
            try {
                Object o2 = callRandom(seed, i, objectId, o, m);
                if (o2 != null) {
                    objects.add(o2);
                }
            } catch (RuntimeException e) {
                Throwable cause = e.getCause();
                if (cause instanceof UnsupportedOperationException) {
                    unsupportedOps.add(e);
                } else {
                    throw e;
                }
            }
        }
        if (!unsupportedOps.isEmpty()) {
            throw unsupportedOps.get(0);
        }

        try {
            if (conn != null) {
                conn.close();
            }
            c1.close();
        } catch (Throwable t) {
            printIfBad(seed, -101010, -1, t);
            try {
                deleteDb();
            } catch (Throwable t2) {
                printIfBad(seed, -101010, -1, t2);
            }
        }
        objects.clear();
    }

    private void printError(int seed, int id, Throwable t) {
        StringWriter writer = new StringWriter();
        t.printStackTrace(new PrintWriter(writer));
        String s = writer.toString();
        TestBase.logError("new TestCrashAPI().init(test).testCase(" +
                seed + "); // Bug " + s.hashCode() + " id=" + id +
                " callCount=" + callCount + " openCount=" + openCount +
                " " + t.getMessage(), t);
        throw new RuntimeException(t);
    }

    private Object callRandom(int seed, int id, int objectId, Object o, Method m) {
        Class<?>[] paramClasses = m.getParameterTypes();
        Object[] params = new Object[paramClasses.length];
        for (int i = 0; i < params.length; i++) {
            params[i] = getRandomParam(paramClasses[i]);
        }
        Object result = null;
        try {
            callCount++;
            result = m.invoke(o, params);
        } catch (IllegalArgumentException e) {
            TestBase.logError("error", e);
        } catch (IllegalAccessException e) {
            TestBase.logError("error", e);
        } catch (InvocationTargetException e) {
            Throwable t = e.getTargetException();
            printIfBad(seed, id, objectId, t);
        }
        if (result == null) {
            return null;
        }
        Class<?> in = getJdbcInterface(result);
        if (in == null) {
            return null;
        }
        return result;
    }

    private void printIfBad(int seed, int id, int objectId, Throwable t) {
        if (t instanceof BatchUpdateException) {
            // do nothing
        } else if (t.getClass().getName().indexOf("SQLClientInfoException") >= 0) {
            // do nothing
        } else if (t instanceof SQLException) {
            SQLException s = (SQLException) t;
            int errorCode = s.getErrorCode();
            if (errorCode == 0) {
                printError(seed, id, s);
            } else if (errorCode == ErrorCode.OBJECT_CLOSED) {
                if (objectId >= 0 && objects.size() > 0) {
                    // TODO at least call a few more times after close - maybe
                    // there is still an error
                    objects.remove(objectId);
                }
            } else if (errorCode == ErrorCode.GENERAL_ERROR_1) {
                // General error [HY000]
                printError(seed, id, s);
            }
        } else {
            printError(seed, id, t);
        }
    }

    private Object getRandomParam(Class<?> type) {
        if (type == int.class) {
            return random.getRandomInt();
        } else if (type == byte.class) {
            return (byte) random.getRandomInt();
        } else if (type == short.class) {
            return (short) random.getRandomInt();
        } else if (type == long.class) {
            return random.getRandomLong();
        } else if (type == float.class) {
            return (float) random.getRandomDouble();
        } else if (type == boolean.class) {
            return random.nextBoolean();
        } else if (type == double.class) {
            return new Double(random.getRandomDouble());
        } else if (type == String.class) {
            if (random.getInt(10) == 0) {
                return null;
            }
            int randomId = random.getInt(statements.size());
            String sql = statements.get(randomId);
            if (random.getInt(10) == 0) {
                sql = random.modify(sql);
            }
            return sql;
        } else if (type == int[].class) {
            // TODO test with 'shared' arrays (make sure database creates a
            // copy)
            return random.getIntArray();
        } else if (type == java.io.Reader.class) {
            return null;
        } else if (type == java.sql.Array.class) {
            return null;
        } else if (type == byte[].class) {
            // TODO test with 'shared' arrays (make sure database creates a
            // copy)
            return random.getByteArray();
        } else if (type == Map.class) {
            return null;
        } else if (type == Object.class) {
            return null;
        } else if (type == java.sql.Date.class) {
            return random.randomDate();
        } else if (type == java.sql.Time.class) {
            return random.randomTime();
        } else if (type == java.sql.Timestamp.class) {
            return random.randomTimestamp();
        } else if (type == java.io.InputStream.class) {
            return null;
        } else if (type == String[].class) {
            return null;
        } else if (type == java.sql.Clob.class) {
            return null;
        } else if (type == java.sql.Blob.class) {
            return null;
        } else if (type == Savepoint.class) {
            // TODO should use generated savepoints
            return null;
        } else if (type == Calendar.class) {
            return Calendar.getInstance();
        } else if (type == java.net.URL.class) {
            return null;
        } else if (type == java.math.BigDecimal.class) {
            return new java.math.BigDecimal("" + random.getRandomDouble());
        } else if (type == java.sql.Ref.class) {
            return null;
        }
        return null;
    }

    private Class<?> getJdbcInterface(Object o) {
        for (Class <?> in : o.getClass().getInterfaces()) {
            if (classMethods.get(in) != null) {
                return in;
            }
        }
        return null;
    }

    private void initMethods() {
        for (Class<?> inter : INTERFACES) {
            List<Method> methods = filterMethods(inter);
            classMethods.put(inter, methods);
        }
    }

    List<Method> filterMethods(Class<?> inter) {
        // Temporarily skip the new api in JDBC 4.2(Java 8)
        List<Method> filter = new ArrayList<>();
        for (Method method: inter.getMethods()) {
            String clazz = inter.getName();
            String name = method.getName();
            if (Statement.class.isAssignableFrom(inter)) {
                switch (name) {
                    case "setLargeMaxRows":
                    case "executeLargeUpdate":
                    case "executeLargeBatch":
                    case "getLargeUpdateCount":
                        printTime("Temporarily skip "+ clazz + "."+ name + "()");
                        continue;
                }
            }
            if (PreparedStatement.class.isAssignableFrom(inter)) {
                if (name.equals("setObject")) {
                    printTime("Temporarily skip "+ clazz + "."+ name + "()");
                    continue;
                }
            }
            if (CallableStatement.class.isAssignableFrom(inter)) {
                if (name.equals("registerOutParameter")) {
                    printTime("Temporarily skip "+ clazz + "."+ name + "()");
                    continue;
                }
            }

            if (ResultSet.class.isAssignableFrom(inter)) {
                if (name.equals("updateObject")) {
                    printTime("Temporarily skip "+ clazz + "."+ name + "()");
                    continue;
                }
            }

            filter.add(method);
        }
        return filter;
    }

    @Override
    public TestBase init(TestAll conf) throws Exception {
        super.init(conf);
        if (config.mvcc || config.networked) {
            return this;
        }
        startServerIfRequired();
        TestScript script = new TestScript();
        ArrayList<String> add = script.getAllStatements(config);
        initMethods();
        org.h2.Driver.load();
        statements.addAll(add);
        return this;
    }

}
