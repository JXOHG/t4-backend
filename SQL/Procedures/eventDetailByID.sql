DELIMITER $$

CREATE PROCEDURE GetEventDetails(IN event_id INT)
BEGIN
    SELECT e.title, e.description, e.event_date, e.location, 
           d.image_url, d.document_url, d.external_link
    FROM Event e
    LEFT JOIN Event_Detail d ON e.event_id = d.event_id
    WHERE e.event_id = event_id;
END $$

DELIMITER ;