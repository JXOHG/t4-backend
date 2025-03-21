DELIMITER $$

CREATE PROCEDURE GetManagedEvents(IN user_id INT)
BEGIN
    SELECT e.event_id, e.title, e.description, e.event_date, e.location
    FROM Event e
    JOIN Manages m ON e.event_id = m.event_id
    WHERE m.user_id = user_id;  -- Add a semicolon here
END$$

DELIMITER ;