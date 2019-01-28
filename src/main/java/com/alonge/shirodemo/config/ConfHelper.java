package com.alonge.shirodemo.config;


import java.io.IOException;
import java.util.Properties;

/**
 * <p>Title : ConfHelper</p>
 * <p>Description : 配置辅助类</p>
 *
 * @author utor wuyanlong
 */
public class ConfHelper {

    /**
     * 配置文件对象
     */
    private static Properties CONF = new Properties();

    /**
     * 加载配置
     */
    static {
        // 加载配置信息
        try {
            CONF.load(ConfHelper.class.getResourceAsStream("/global-config.properties"));
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 获取对应的value
     *
     * @param key 对应的key
     * @return 对应的值
     */
    public static String getValue(String key) {

        return CONF.getProperty(key);
    }
}