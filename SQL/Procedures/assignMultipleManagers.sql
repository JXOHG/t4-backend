DELIMITER $$

CREATE PROCEDURE AssignMultipleManagers(
    IN event_id INT,
    IN user_ids TEXT
)
BEGIN
    DECLARE user_id INT;
    DECLARE done INT DEFAULT 0;
    DECLARE user_cursor CURSOR FOR
        SELECT CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(user_ids, ',', n.n), ',', -1) AS UNSIGNED)
        FROM   (SELECT 1 AS n UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5
                UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10) n
        WHERE   n.n <= 1 + (LENGTH(user_ids) - LENGTH(REPLACE(user_ids, ',', ''))) AND user_ids != '';
    
    OPEN user_cursor;
    
    read_loop: LOOP
        FETCH user_cursor INTO user_id;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        INSERT INTO Manages (user_id, event_id) VALUES (user_id, event_id);
    END LOOP;
    
    CLOSE user_cursor;
END $$

DELIMITER ;